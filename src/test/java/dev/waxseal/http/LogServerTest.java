package dev.waxseal.http;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.waxseal.log.Checkpoint;
import dev.waxseal.log.TransparencyLog;
import dev.waxseal.witness.Witness;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class LogServerTest {

    private static final String TOKEN = "correct-horse-battery-staple";

    @TempDir
    Path directory;

    private final HttpClient http = HttpClient.newHttpClient();
    private TransparencyLog log;
    private LogServer server;
    private RemoteLog remote;
    private String base;

    @BeforeEach
    void setUp() throws IOException {
        log = TransparencyLog.create(directory.resolve("log"), "test.waxseal");
        server = new LogServer(log, new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), TOKEN);
        server.start();
        base = "http://127.0.0.1:" + server.port();
        remote = new RemoteLog(URI.create(base + "/"));
    }

    @AfterEach
    void tearDown() throws IOException {
        server.close();
        log.close();
    }

    @Test
    void aRemoteWitnessCanAuditTheLogEndToEnd() throws Exception {
        Witness witness = new Witness(remote.publicKey(), directory.resolve("witness-checkpoint"));

        for (int i = 0; i < 5; i++) {
            assertEquals(i, remote.append(bytes("event " + i), TOKEN));
        }
        Checkpoint first = remote.checkpoint();
        witness.advance(first, List.of());

        for (int i = 5; i < 13; i++) {
            remote.append(bytes("event " + i), TOKEN);
        }
        Checkpoint second = remote.checkpoint();
        witness.advance(second, remote.consistencyProof(first.treeSize(), second.treeSize()));
        assertEquals(13, witness.trusted().orElseThrow().treeSize());

        byte[] entry = remote.entry(7);
        assertArrayEquals(bytes("event 7"), entry);
        assertTrue(witness.verifyInclusion(entry, 7, remote.inclusionProof(7, second.treeSize())));
    }

    @Test
    void appendingRequiresTheToken() throws Exception {
        assertEquals(401, post("/v1/entries", "event", null).statusCode());
        assertEquals(401, post("/v1/entries", "event", "Bearer wrong-token-wrong-token").statusCode());
        assertEquals(401, post("/v1/entries", "event", "Bearer " + TOKEN + "x").statusCode());
        assertEquals(401, post("/v1/entries", "event", "Basic " + TOKEN).statusCode());
        assertEquals(0, log.size(), "nothing was appended");

        assertEquals(201, post("/v1/entries", "event", "Bearer " + TOKEN).statusCode());
        assertEquals(1, log.size());
    }

    @Test
    void rejectsEmptyAndOversizedEntries() throws Exception {
        assertEquals(400, post("/v1/entries", "", "Bearer " + TOKEN).statusCode());
        String tooLarge = "x".repeat(TransparencyLog.MAX_ENTRY_BYTES + 1);
        assertEquals(413, post("/v1/entries", tooLarge, "Bearer " + TOKEN).statusCode());
        assertEquals(0, log.size());
    }

    @Test
    void answersBadRequestsWithoutLeakingDetails() throws Exception {
        log.append(bytes("a"));

        assertEquals(404, get("/nope").statusCode());
        assertEquals(404, get("/v1/unknown").statusCode());
        assertEquals(405, get("/v1/entries").statusCode());
        assertEquals(405, post("/v1/checkpoint", "x", null).statusCode());
        assertEquals(400, get("/v1/entries/99").statusCode());
        assertEquals(400, get("/v1/entries/-1").statusCode());
        assertEquals(400, get("/v1/proofs/inclusion?index=0").statusCode());
        assertEquals(400, get("/v1/proofs/consistency?from=5&to=2").statusCode());

        HttpResponse<String> response = get("/v1/entries/abc%3Cscript%3E");
        assertEquals(400, response.statusCode());
        assertEquals("bad request\n", response.body(), "the invalid input is not echoed back");
    }

    @Test
    void servesEntriesAsOpaqueBytes() throws Exception {
        log.append(bytes("<script>alert(1)</script>"));

        HttpResponse<String> response = get("/v1/entries/0");
        assertEquals(200, response.statusCode());
        assertEquals("application/octet-stream", response.headers().firstValue("Content-Type").orElseThrow());
        assertEquals("nosniff", response.headers().firstValue("X-Content-Type-Options").orElseThrow());
    }

    @Test
    void refusesWeakWriteTokens() {
        InetSocketAddress address = new InetSocketAddress(InetAddress.getLoopbackAddress(), 0);
        assertThrows(IllegalArgumentException.class, () -> new LogServer(log, address, "short"));
        assertThrows(IllegalArgumentException.class, () -> new LogServer(log, address, null));
    }

    private HttpResponse<String> get(String path) throws IOException, InterruptedException {
        return http.send(HttpRequest.newBuilder(URI.create(base + path)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> post(String path, String body, String authorization)
            throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(base + path))
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (authorization != null) {
            request.header("Authorization", authorization);
        }
        return http.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
