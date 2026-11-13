package dev.waxseal.cli;

import dev.waxseal.log.Checkpoint;
import dev.waxseal.log.Keys;
import dev.waxseal.log.TamperedLogException;
import dev.waxseal.log.TransparencyLog;
import dev.waxseal.witness.MisbehaviorException;
import dev.waxseal.witness.Witness;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;
import java.util.zip.CRC32C;

/**
 * Walkthrough of the two attacks the log is built to expose: an intruder editing the files, and
 * an insider who holds the signing key rewriting the whole history.
 */
final class Demo {

    private static final String ORIGIN = "demo.waxseal";

    private static final String[] EVENTS = {
        "2026-01-10T09:12:03Z user=ana     action=LOGIN    ip=10.0.0.7",
        "2026-01-10T09:14:40Z user=ana     action=TRANSFER amount=100.00 to=acct-7781",
        "2026-01-10T09:15:02Z user=root    action=GRANT    role=admin target=mallory",
        "2026-01-10T09:20:19Z user=mallory action=EXPORT   table=customers rows=48210",
        "2026-01-10T09:21:00Z user=mallory action=LOGOUT",
    };

    private static final String[] LATER_EVENTS = {
        "2026-01-10T10:02:11Z user=bruno   action=LOGIN    ip=10.0.0.9",
        "2026-01-10T10:05:37Z user=bruno   action=UPDATE   table=orders id=5521",
        "2026-01-10T10:09:54Z user=bruno   action=LOGOUT",
    };

    /** The entry an attacker would most like to make disappear, and what they would write instead. */
    private static final int INCRIMINATING = 2;
    private static final String COVER_STORY = pad("2026-01-10T09:15:02Z user=root    action=PING     host=db01",
            EVENTS[INCRIMINATING].length());

    private Demo() {
    }

    static void run() throws Exception {
        Path workspace = Files.createTempDirectory("waxseal-demo");
        try {
            story(workspace);
        } finally {
            deleteRecursively(workspace);
        }
    }

    private static void story(Path workspace) throws Exception {
        Path logDirectory = workspace.resolve("log");
        KeyPair keys = Keys.generate();

        step("1. An application records audit events");
        Checkpoint first;
        try (TransparencyLog log = TransparencyLog.create(logDirectory, ORIGIN, keys)) {
            for (String event : EVENTS) {
                log.append(bytes(event));
            }
            first = log.checkpoint();
        }
        for (int i = 0; i < EVENTS.length; i++) {
            System.out.println("   [" + i + "] " + EVENTS[i]);
        }
        System.out.println("   signed checkpoint: size=" + first.treeSize() + " root=" + shortHex(first.rootHash()));

        step("2. An independent witness stores that checkpoint");
        Witness witness = new Witness(keys.getPublic(), workspace.resolve("witness-checkpoint"));
        witness.advance(first, List.of());
        System.out.println("   witness now trusts size=" + first.treeSize());

        step("3. The log grows, and must prove it only appended");
        Checkpoint second;
        try (TransparencyLog log = TransparencyLog.open(logDirectory)) {
            for (String event : LATER_EVENTS) {
                log.append(bytes(event));
            }
            second = log.checkpoint();
            List<byte[]> consistency = log.consistencyProof(first.treeSize(), second.treeSize());
            witness.advance(second, consistency);
            System.out.println("   [ok] consistency proof " + first.treeSize() + " -> " + second.treeSize()
                    + " accepted (" + consistency.size() + " hashes)");

            List<byte[]> inclusion = log.inclusionProof(INCRIMINATING, second.treeSize());
            boolean included = witness.verifyInclusion(bytes(EVENTS[INCRIMINATING]), INCRIMINATING, inclusion);
            System.out.println("   [" + (included ? "ok" : "FAILED") + "] entry " + INCRIMINATING
                    + " proven to be in the log with " + inclusion.size() + " hashes, without reading the other "
                    + (second.treeSize() - 1) + " entries");
        }

        step("4. ATTACK A: an intruder edits the file on disk and repairs the checksum");
        System.out.println("   before: " + EVENTS[INCRIMINATING]);
        System.out.println("   after:  " + COVER_STORY);
        rewriteEntryOnDisk(logDirectory.resolve("entries.dat"), bytes(EVENTS[INCRIMINATING]), bytes(COVER_STORY));
        try {
            TransparencyLog.open(logDirectory).close();
            System.out.println("   [NOT DETECTED] this must never be printed");
        } catch (TamperedLogException e) {
            System.out.println("   [DETECTED] " + e.getMessage());
        }

        step("5. ATTACK B: an insider with the signing key rewrites everything and signs it again");
        Path forgedDirectory = workspace.resolve("forged");
        Checkpoint forged;
        List<byte[]> forgedProof;
        try (TransparencyLog log = TransparencyLog.create(forgedDirectory, ORIGIN, keys)) {
            for (String event : Stream.concat(Arrays.stream(EVENTS), Arrays.stream(LATER_EVENTS)).toList()) {
                log.append(bytes(event.equals(EVENTS[INCRIMINATING]) ? COVER_STORY : event));
            }
            log.append(bytes("2026-01-10T11:00:00Z user=carla   action=LOGIN    ip=10.0.0.12"));
            forged = log.checkpoint();
            forgedProof = log.consistencyProof(second.treeSize(), forged.treeSize());
        }
        try (TransparencyLog log = TransparencyLog.open(forgedDirectory)) {
            System.out.println("   the forged log is internally flawless: " + log.size()
                    + " entries, valid signature, every hash matches");
        }
        try {
            witness.advance(forged, forgedProof);
            System.out.println("   [NOT DETECTED] this must never be printed");
        } catch (MisbehaviorException e) {
            System.out.println("   [DETECTED by the witness: " + e.reason() + "] " + e.getMessage());
        }

        System.out.println();
        System.out.println("A signature shows who wrote the log. Only the consistency proof shows that");
        System.out.println("nobody, not even the key holder, rewrote what was already there.");
    }

    /**
     * What an attacker with write access to the disk would do: replace one entry in place and
     * recompute its checksum, so the file still looks perfectly healthy.
     */
    private static void rewriteEntryOnDisk(Path file, byte[] original, byte[] replacement) throws IOException {
        byte[] content = Files.readAllBytes(file);
        int position = indexOf(content, original);
        if (position < 0 || original.length != replacement.length) {
            throw new IllegalStateException("demo entry not found");
        }
        System.arraycopy(replacement, 0, content, position, replacement.length);
        CRC32C checksum = new CRC32C();
        checksum.update(replacement);
        ByteBuffer.wrap(content).putInt(position + replacement.length, (int) checksum.getValue());
        Files.write(file, content);
    }

    private static int indexOf(byte[] haystack, byte[] needle) {
        for (int i = 0; i <= haystack.length - needle.length; i++) {
            if (Arrays.equals(haystack, i, i + needle.length, needle, 0, needle.length)) {
                return i;
            }
        }
        return -1;
    }

    private static void step(String title) {
        System.out.println();
        System.out.println(title);
    }

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    private static String shortHex(byte[] hash) {
        return Main.hex(hash).substring(0, 16) + "...";
    }

    private static String pad(String text, int length) {
        return text + " ".repeat(length - text.length());
    }

    private static void deleteRecursively(Path directory) throws IOException {
        try (Stream<Path> paths = Files.walk(directory)) {
            for (Path path : paths.sorted(Comparator.reverseOrder()).toList()) {
                Files.delete(path);
            }
        }
    }
}
