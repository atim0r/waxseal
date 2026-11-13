package dev.waxseal.http;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import dev.waxseal.log.Keys;
import dev.waxseal.log.TransparencyLog;
import dev.waxseal.merkle.Hashing;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * HTTP front end for a log, built on the JDK's own server.
 *
 * <p>Reading is public by design: checkpoints, entries and proofs are exactly what outsiders need
 * in order to audit the log. Appending requires a bearer token.
 *
 * <pre>
 * GET  /v1/checkpoint                         latest signed checkpoint
 * GET  /v1/pubkey                             log public key (base64, X.509)
 * GET  /v1/entries/{index}                    raw entry
 * POST /v1/entries                            append the request body (needs the token)
 * GET  /v1/proofs/inclusion?index=I&amp;size=N    audit path, one base64 hash per line
 * GET  /v1/proofs/consistency?from=M&amp;to=N     consistency proof, one base64 hash per line
 * </pre>
 */
public final class LogServer implements AutoCloseable {

    private static final System.Logger LOGGER = System.getLogger(LogServer.class.getName());
    private static final int MIN_TOKEN_LENGTH = 16;

    private final TransparencyLog log;
    private final byte[] tokenDigest;
    private final HttpServer server;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

    public LogServer(TransparencyLog log, InetSocketAddress address, String writeToken) throws IOException {
        if (writeToken == null || writeToken.length() < MIN_TOKEN_LENGTH) {
            throw new IllegalArgumentException("write token needs at least " + MIN_TOKEN_LENGTH + " characters");
        }
        this.log = log;
        this.tokenDigest = digest(writeToken);
        this.server = HttpServer.create(address, 0);
        this.server.createContext("/", this::handle);
        this.server.setExecutor(executor);
    }

    public void start() {
        server.start();
    }

    public int port() {
        return server.getAddress().getPort();
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }

    private void handle(HttpExchange exchange) throws IOException {
        try (exchange) {
            try {
                route(exchange);
            } catch (HttpError e) {
                sendText(exchange, e.status, e.getMessage() + "\n");
            } catch (IllegalArgumentException e) {
                // Malformed numbers and out-of-range indexes. The input is not echoed back.
                sendText(exchange, 400, "bad request\n");
            } catch (IOException | RuntimeException e) {
                // Details go to the server log only; clients learn nothing about internals.
                LOGGER.log(System.Logger.Level.ERROR, "request failed", e);
                sendText(exchange, 500, "internal error\n");
            }
        }
    }

    private void route(HttpExchange exchange) throws IOException {
        String method = exchange.getRequestMethod();
        String path = exchange.getRequestURI().getPath();
        Map<String, String> query = parseQuery(exchange.getRequestURI().getRawQuery());

        switch (path) {
            case "/v1/checkpoint" -> {
                require(method, "GET");
                sendText(exchange, 200, log.checkpoint().encode());
            }
            case "/v1/pubkey" -> {
                require(method, "GET");
                sendText(exchange, 200, Keys.encodePublic(log.publicKey()) + "\n");
            }
            case "/v1/entries" -> {
                require(method, "POST");
                authorize(exchange);
                long index = log.append(readBody(exchange));
                sendText(exchange, 201, index + "\n");
            }
            case "/v1/proofs/inclusion" -> {
                require(method, "GET");
                sendText(exchange, 200, encodeProof(
                        log.inclusionProof(longParameter(query, "index"), longParameter(query, "size"))));
            }
            case "/v1/proofs/consistency" -> {
                require(method, "GET");
                sendText(exchange, 200, encodeProof(
                        log.consistencyProof(longParameter(query, "from"), longParameter(query, "to"))));
            }
            default -> {
                if (!path.startsWith("/v1/entries/")) {
                    throw new HttpError(404, "not found");
                }
                require(method, "GET");
                long index = Long.parseLong(path.substring("/v1/entries/".length()));
                send(exchange, 200, "application/octet-stream", log.entry(index));
            }
        }
    }

    private void authorize(HttpExchange exchange) {
        String header = exchange.getRequestHeaders().getFirst("Authorization");
        String prefix = "Bearer ";
        // Both sides are hashed first, so the comparison is constant-time and leaks neither the
        // token's content nor its length through timing.
        if (header == null || !header.startsWith(prefix)
                || !MessageDigest.isEqual(digest(header.substring(prefix.length())), tokenDigest)) {
            exchange.getResponseHeaders().set("WWW-Authenticate", "Bearer");
            throw new HttpError(401, "unauthorized");
        }
    }

    private static byte[] readBody(HttpExchange exchange) throws IOException {
        byte[] body = exchange.getRequestBody().readNBytes(TransparencyLog.MAX_ENTRY_BYTES + 1);
        if (body.length > TransparencyLog.MAX_ENTRY_BYTES) {
            throw new HttpError(413, "entry too large");
        }
        if (body.length == 0) {
            throw new HttpError(400, "empty entry");
        }
        return body;
    }

    private static void require(String actual, String expected) {
        if (!actual.equals(expected)) {
            throw new HttpError(405, "method not allowed");
        }
    }

    private static Map<String, String> parseQuery(String rawQuery) {
        Map<String, String> parameters = new HashMap<>();
        if (rawQuery != null) {
            for (String pair : rawQuery.split("&")) {
                int separator = pair.indexOf('=');
                if (separator > 0) {
                    parameters.put(URLDecoder.decode(pair.substring(0, separator), StandardCharsets.UTF_8),
                            URLDecoder.decode(pair.substring(separator + 1), StandardCharsets.UTF_8));
                }
            }
        }
        return parameters;
    }

    private static long longParameter(Map<String, String> query, String name) {
        String value = query.get(name);
        if (value == null) {
            throw new IllegalArgumentException("missing parameter " + name);
        }
        return Long.parseLong(value);
    }

    static String encodeProof(List<byte[]> proof) {
        StringBuilder text = new StringBuilder();
        for (byte[] hash : proof) {
            text.append(Base64.getEncoder().encodeToString(hash)).append('\n');
        }
        return text.toString();
    }

    private static void sendText(HttpExchange exchange, int status, String text) throws IOException {
        send(exchange, status, "text/plain; charset=utf-8", text.getBytes(StandardCharsets.UTF_8));
    }

    private static void send(HttpExchange exchange, int status, String contentType, byte[] body) throws IOException {
        exchange.getResponseHeaders().set("Content-Type", contentType);
        // Entries are attacker-influenced bytes: never let a browser guess they are HTML.
        exchange.getResponseHeaders().set("X-Content-Type-Options", "nosniff");
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
        if (body.length > 0) {
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        }
    }

    private static byte[] digest(String value) {
        return Hashing.sha256().digest(value.getBytes(StandardCharsets.UTF_8));
    }

    private static final class HttpError extends RuntimeException {

        private static final long serialVersionUID = 1L;

        private final int status;

        HttpError(int status, String message) {
            super(message);
            this.status = status;
        }
    }
}
