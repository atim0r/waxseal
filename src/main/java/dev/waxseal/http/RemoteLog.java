package dev.waxseal.http;

import dev.waxseal.log.Checkpoint;
import dev.waxseal.log.Keys;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Client for {@link LogServer}. Nothing it returns is trusted by itself: callers verify
 * checkpoints and proofs with {@code Witness} or {@code ProofVerifier}.
 */
public final class RemoteLog {

    private static final Duration TIMEOUT = Duration.ofSeconds(10);

    private final HttpClient http = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
    private final String base;

    public RemoteLog(URI base) {
        String text = base.toString();
        this.base = text.endsWith("/") ? text.substring(0, text.length() - 1) : text;
    }

    public Checkpoint checkpoint() throws IOException, InterruptedException {
        try {
            return Checkpoint.parse(text(get("/v1/checkpoint")));
        } catch (IllegalArgumentException e) {
            throw new IOException("log server returned a malformed checkpoint", e);
        }
    }

    public PublicKey publicKey() throws IOException, InterruptedException {
        try {
            return Keys.decodePublic(text(get("/v1/pubkey")));
        } catch (IllegalArgumentException e) {
            throw new IOException("log server returned a malformed public key", e);
        }
    }

    public byte[] entry(long index) throws IOException, InterruptedException {
        return get("/v1/entries/" + index);
    }

    public List<byte[]> inclusionProof(long index, long treeSize) throws IOException, InterruptedException {
        return decodeProof(text(get("/v1/proofs/inclusion?index=" + index + "&size=" + treeSize)));
    }

    public List<byte[]> consistencyProof(long first, long second) throws IOException, InterruptedException {
        return decodeProof(text(get("/v1/proofs/consistency?from=" + first + "&to=" + second)));
    }

    /** Appends an entry and returns its index. */
    public long append(byte[] entry, String token) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(base + "/v1/entries"))
                .timeout(TIMEOUT)
                .header("Authorization", "Bearer " + token)
                .POST(HttpRequest.BodyPublishers.ofByteArray(entry))
                .build();
        HttpResponse<byte[]> response = http.send(request, HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 201) {
            throw new IOException("log server refused the entry: HTTP " + response.statusCode());
        }
        try {
            return Long.parseLong(text(response.body()).strip());
        } catch (NumberFormatException e) {
            throw new IOException("log server returned a malformed index", e);
        }
    }

    private byte[] get(String path) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(base + path)).timeout(TIMEOUT).GET().build();
        HttpResponse<byte[]> response = http.send(request, HttpResponse.BodyHandlers.ofByteArray());
        if (response.statusCode() != 200) {
            throw new IOException("log server answered HTTP " + response.statusCode() + " for " + path);
        }
        return response.body();
    }

    private static List<byte[]> decodeProof(String text) throws IOException {
        List<byte[]> proof = new ArrayList<>();
        try {
            for (String line : text.split("\n")) {
                if (!line.isEmpty()) {
                    proof.add(Base64.getDecoder().decode(line));
                }
            }
        } catch (IllegalArgumentException e) {
            throw new IOException("log server returned a malformed proof", e);
        }
        return proof;
    }

    private static String text(byte[] body) {
        return new String(body, StandardCharsets.UTF_8);
    }
}
