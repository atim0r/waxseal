package dev.waxseal.cli;

import dev.waxseal.http.LogServer;
import dev.waxseal.http.RemoteLog;
import dev.waxseal.log.Checkpoint;
import dev.waxseal.log.Keys;
import dev.waxseal.log.TamperedLogException;
import dev.waxseal.log.TransparencyLog;
import dev.waxseal.merkle.Hashing;
import dev.waxseal.merkle.ProofVerifier;
import dev.waxseal.witness.MisbehaviorException;
import dev.waxseal.witness.Witness;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CountDownLatch;

/** Command-line entry point. Exit code 2 means tampering or log misbehavior was detected. */
public final class Main {

    private static final String USAGE = """
            waxseal - tamper-evident audit log

              waxseal demo                          run the attack-and-detection walkthrough
              waxseal init <dir> <origin>           create a log and its signing key
              waxseal append <dir> <text>           append an entry
              waxseal checkpoint <dir>              sign and print the current state
              waxseal verify <dir>                  check stored entries against signed checkpoints
              waxseal prove <dir> <index>           print and check an inclusion proof
              waxseal serve <dir> [port]            serve the log over HTTP on 127.0.0.1
              waxseal witness <url> <state-dir>     audit a remote log, remembering what was seen
            """;

    private Main() {
    }

    public static void main(String[] args) {
        int exitCode;
        try {
            exitCode = run(args);
        } catch (TamperedLogException e) {
            System.err.println("TAMPERING DETECTED: " + e.getMessage());
            exitCode = 2;
        } catch (MisbehaviorException e) {
            System.err.println("LOG MISBEHAVIOR [" + e.reason() + "]: " + e.getMessage());
            exitCode = 2;
        } catch (IllegalArgumentException | IOException e) {
            System.err.println("error: " + e.getMessage());
            exitCode = 1;
        } catch (Exception e) {
            e.printStackTrace();
            exitCode = 1;
        }
        System.exit(exitCode);
    }

    private static int run(String[] args) throws Exception {
        if (args.length == 0) {
            System.out.print(USAGE);
            return 1;
        }
        String[] rest = Arrays.copyOfRange(args, 1, args.length);
        switch (args[0]) {
            case "demo" -> Demo.run();
            case "init" -> init(argument(rest, 0), argument(rest, 1));
            case "append" -> append(argument(rest, 0), String.join(" ", Arrays.copyOfRange(rest, 1, rest.length)));
            case "checkpoint" -> checkpoint(argument(rest, 0));
            case "verify" -> verify(argument(rest, 0));
            case "prove" -> prove(argument(rest, 0), Long.parseLong(argument(rest, 1)));
            case "serve" -> serve(argument(rest, 0), rest.length > 1 ? Integer.parseInt(rest[1]) : 8080);
            case "witness" -> witness(argument(rest, 0), argument(rest, 1));
            default -> {
                System.out.print(USAGE);
                return 1;
            }
        }
        return 0;
    }

    private static void init(String directory, String origin) throws IOException {
        try (TransparencyLog log = TransparencyLog.create(Path.of(directory), origin)) {
            System.out.println("created log '" + log.origin() + "' in " + directory);
            System.out.println("public key fingerprint: " + Keys.fingerprint(log.publicKey()));
        }
    }

    private static void append(String directory, String text) throws IOException {
        if (text.isEmpty()) {
            throw new IllegalArgumentException("nothing to append");
        }
        try (TransparencyLog log = TransparencyLog.open(Path.of(directory))) {
            long index = log.append(text.getBytes(StandardCharsets.UTF_8));
            System.out.println("appended entry " + index);
        }
    }

    private static void checkpoint(String directory) throws IOException {
        try (TransparencyLog log = TransparencyLog.open(Path.of(directory))) {
            System.out.print(log.checkpoint().encode());
        }
    }

    private static void verify(String directory) throws IOException {
        try (TransparencyLog log = TransparencyLog.open(Path.of(directory))) {
            String covered = log.latestCheckpoint()
                    .map(checkpoint -> checkpoint.treeSize() + " covered by signed checkpoints")
                    .orElse("none covered by a checkpoint yet");
            System.out.println("OK: " + log.size() + " entries, " + covered);
        }
    }

    private static void prove(String directory, long index) throws IOException {
        try (TransparencyLog log = TransparencyLog.open(Path.of(directory))) {
            Checkpoint checkpoint = log.checkpoint();
            byte[] entry = log.entry(index);
            List<byte[]> proof = log.inclusionProof(index, checkpoint.treeSize());
            System.out.println("entry " + index + ": " + new String(entry, StandardCharsets.UTF_8));
            System.out.println("root at size " + checkpoint.treeSize() + ": " + hex(checkpoint.rootHash()));
            for (byte[] hash : proof) {
                System.out.println("  path: " + hex(hash));
            }
            boolean valid = ProofVerifier.verifyInclusion(index, checkpoint.treeSize(), Hashing.leafHash(entry),
                    proof, checkpoint.rootHash());
            System.out.println(valid ? "proof verifies" : "PROOF DOES NOT VERIFY");
        }
    }

    private static void serve(String directory, int port) throws IOException, InterruptedException {
        String token = System.getenv("WAXSEAL_TOKEN");
        boolean generated = token == null || token.isBlank();
        if (generated) {
            byte[] random = new byte[32];
            new SecureRandom().nextBytes(random);
            token = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        }
        TransparencyLog log = TransparencyLog.open(Path.of(directory));
        LogServer server = new LogServer(log, new InetSocketAddress(InetAddress.getLoopbackAddress(), port), token);
        server.start();
        System.out.println("serving '" + log.origin() + "' on http://127.0.0.1:" + server.port());
        System.out.println("public key fingerprint: " + Keys.fingerprint(log.publicKey()));
        if (generated) {
            System.out.println("write token for this run (set WAXSEAL_TOKEN to choose your own): " + token);
        }
        new CountDownLatch(1).await();
    }

    private static void witness(String url, String stateDirectory) throws Exception {
        RemoteLog remote = new RemoteLog(URI.create(url));
        Path directory = Files.createDirectories(Path.of(stateDirectory));
        Path keyFile = directory.resolve("log.pub");

        PublicKey key;
        if (Files.exists(keyFile)) {
            key = Keys.decodePublic(Files.readString(keyFile));
        } else {
            key = remote.publicKey();
            Files.writeString(keyFile, Keys.encodePublic(key) + "\n");
            System.out.println("first contact: pinned log key " + Keys.fingerprint(key)
                    + " (compare this fingerprint with the log operator out of band)");
        }

        Witness witness = new Witness(key, directory.resolve("checkpoint"));
        Checkpoint next = remote.checkpoint();
        long trustedSize = witness.trusted().map(Checkpoint::treeSize).orElse(0L);
        List<byte[]> proof = trustedSize > 0 && trustedSize < next.treeSize()
                ? remote.consistencyProof(trustedSize, next.treeSize())
                : List.of();
        witness.advance(next, proof);
        System.out.println("OK: log is consistent, " + trustedSize + " -> " + next.treeSize() + " entries");
        System.out.println("root: " + hex(next.rootHash()));
    }

    private static String argument(String[] arguments, int index) {
        if (index >= arguments.length) {
            throw new IllegalArgumentException("missing argument; run without arguments for usage");
        }
        return arguments[index];
    }

    static String hex(byte[] bytes) {
        return HexFormat.of().formatHex(bytes);
    }
}
