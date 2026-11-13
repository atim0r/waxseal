package dev.waxseal.log;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.waxseal.merkle.Hashing;
import dev.waxseal.merkle.ProofVerifier;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class TransparencyLogTest {

    private static final String ORIGIN = "test.waxseal";

    @TempDir
    Path directory;

    @Test
    void entriesAndCheckpointsSurviveAReopen() throws IOException {
        Checkpoint checkpoint;
        try (TransparencyLog log = TransparencyLog.create(directory, ORIGIN)) {
            assertEquals(0, log.append(bytes("first")));
            assertEquals(1, log.append(bytes("second")));
            checkpoint = log.checkpoint();
            assertEquals(2, log.append(bytes("third, after the checkpoint")));
        }
        try (TransparencyLog log = TransparencyLog.open(directory)) {
            assertEquals(3, log.size());
            assertArrayEquals(bytes("second"), log.entry(1));
            assertEquals(checkpoint, log.latestCheckpoint().orElseThrow());
            assertEquals(ORIGIN, log.origin());
            assertEquals(3, log.append(bytes("fourth")));
        }
    }

    @Test
    void checkpointCommitsToTheEntriesAndIsSignedByTheLog() throws IOException {
        try (TransparencyLog log = TransparencyLog.create(directory, ORIGIN)) {
            log.append(bytes("a"));
            log.append(bytes("b"));
            log.append(bytes("c"));
            Checkpoint checkpoint = log.checkpoint();

            assertEquals(3, checkpoint.treeSize());
            assertTrue(checkpoint.verify(log.publicKey()));
            assertFalse(checkpoint.verify(Keys.generate().getPublic()), "another key must not verify");
            assertTrue(ProofVerifier.verifyInclusion(1, 3, Hashing.leafHash(bytes("b")),
                    log.inclusionProof(1, 3), checkpoint.rootHash()));
            assertEquals(checkpoint, Checkpoint.parse(checkpoint.encode()));
        }
    }

    @Test
    void neverSignsTwoStatementsAboutTheSameSize() throws IOException {
        try (TransparencyLog log = TransparencyLog.create(directory, ORIGIN)) {
            log.append(bytes("a"));
            Checkpoint first = log.checkpoint();
            assertEquals(first, log.checkpoint());
            log.append(bytes("b"));
            assertNotEquals(first, log.checkpoint());
        }
    }

    @Test
    void detectsAnEntryRewrittenOnDiskWithARepairedChecksum() throws IOException {
        try (TransparencyLog log = TransparencyLog.create(directory, ORIGIN)) {
            log.append(bytes("user=ana action=TRANSFER amount=100"));
            log.append(bytes("user=root action=GRANT role=admin"));
            log.checkpoint();
        }
        LogFiles.rewriteEntry(directory, "user=ana action=TRANSFER amount=100", "user=ana action=TRANSFER amount=900");

        TamperedLogException error = assertThrows(TamperedLogException.class, () -> TransparencyLog.open(directory));
        assertTrue(error.getMessage().contains("modified"), error.getMessage());
    }

    @Test
    void narrowsTamperingDownToTheRangeBetweenTwoCheckpoints() throws IOException {
        try (TransparencyLog log = TransparencyLog.create(directory, ORIGIN)) {
            for (int i = 0; i < 9; i++) {
                log.append(bytes("event-number-" + i));
                if (i % 3 == 2) {
                    log.checkpoint();
                }
            }
        }
        LogFiles.rewriteEntry(directory, "event-number-4", "event-number-X");

        TamperedLogException error = assertThrows(TamperedLogException.class, () -> TransparencyLog.open(directory));
        assertTrue(error.getMessage().contains("[3, 6)"), error.getMessage());
    }

    @Test
    void detectsDeletionOfCheckpointedEntries() throws IOException {
        try (TransparencyLog log = TransparencyLog.create(directory, ORIGIN)) {
            log.append(bytes("keep me"));
            log.append(bytes("delete me"));
            log.checkpoint();
        }
        LogFiles.truncateBefore(directory, "delete me");

        TamperedLogException error = assertThrows(TamperedLogException.class, () -> TransparencyLog.open(directory));
        assertTrue(error.getMessage().contains("truncated"), error.getMessage());
    }

    @Test
    void detectsAForgedCheckpoint() throws IOException {
        KeyPair attacker = Keys.generate();
        try (TransparencyLog log = TransparencyLog.create(directory, ORIGIN)) {
            log.append(bytes("a"));
            log.checkpoint();
        }
        Checkpoint forged = Checkpoint.sign(ORIGIN, 1, Hashing.leafHash(bytes("a")), 0, attacker.getPrivate());
        Files.writeString(LogFiles.checkpoints(directory), forged.encode() + "\n", StandardOpenOption.APPEND);

        assertThrows(TamperedLogException.class, () -> TransparencyLog.open(directory));
    }

    @Test
    void reportsAccidentalCorruptionSeparatelyFromTampering() throws IOException {
        try (TransparencyLog log = TransparencyLog.create(directory, ORIGIN)) {
            log.append(bytes("bit rot happens"));
        }
        LogFiles.flipBitInside(directory, "bit rot happens");

        assertThrows(CorruptLogException.class, () -> TransparencyLog.open(directory));
    }

    @Test
    void recoversFromAnAppendInterruptedByACrash() throws IOException {
        try (TransparencyLog log = TransparencyLog.create(directory, ORIGIN)) {
            log.append(bytes("complete"));
            log.checkpoint();
        }
        // A record that announces 100 bytes but was cut after 3.
        Files.write(LogFiles.entries(directory), new byte[] {0, 0, 0, 100, 1, 2, 3}, StandardOpenOption.APPEND);

        try (TransparencyLog log = TransparencyLog.open(directory)) {
            assertEquals(1, log.size());
            assertEquals(1, log.append(bytes("written after recovery")));
        }
        try (TransparencyLog log = TransparencyLog.open(directory)) {
            assertEquals(2, log.size());
            assertArrayEquals(bytes("written after recovery"), log.entry(1));
        }
    }

    @Test
    void leavesTheEvidenceUntouchedWhenTamperingIsFound() throws IOException {
        try (TransparencyLog log = TransparencyLog.create(directory, ORIGIN)) {
            log.append(bytes("keep me"));
            log.append(bytes("delete me"));
            log.checkpoint();
        }
        LogFiles.truncateBefore(directory, "delete me");
        Files.write(LogFiles.entries(directory), new byte[] {0, 0, 0, 100, 1, 2, 3}, StandardOpenOption.APPEND);
        byte[] before = Files.readAllBytes(LogFiles.entries(directory));

        assertThrows(TamperedLogException.class, () -> TransparencyLog.open(directory));
        assertArrayEquals(before, Files.readAllBytes(LogFiles.entries(directory)));
    }

    @Test
    void ignoresACheckpointWhoseWriteWasInterrupted() throws IOException {
        try (TransparencyLog log = TransparencyLog.create(directory, ORIGIN)) {
            log.append(bytes("a"));
            log.checkpoint();
        }
        Files.writeString(LogFiles.checkpoints(directory), "waxseal-checkpoint-v1\norigin: te", StandardOpenOption.APPEND);

        try (TransparencyLog log = TransparencyLog.open(directory)) {
            assertEquals(1, log.latestCheckpoint().orElseThrow().treeSize());
            log.append(bytes("b"));
            assertEquals(2, log.checkpoint().treeSize());
        }
        try (TransparencyLog log = TransparencyLog.open(directory)) {
            assertEquals(2, log.latestCheckpoint().orElseThrow().treeSize());
        }
    }

    @Test
    void rejectsOversizedEntriesAndBadOrigins() throws IOException {
        try (TransparencyLog log = TransparencyLog.create(directory, ORIGIN)) {
            assertThrows(IllegalArgumentException.class,
                    () -> log.append(new byte[TransparencyLog.MAX_ENTRY_BYTES + 1]));
            assertEquals(0, log.size());
        }
        assertThrows(IllegalArgumentException.class,
                () -> TransparencyLog.create(directory.resolve("other"), "two\nlines"));
        assertThrows(IOException.class, () -> TransparencyLog.create(directory, ORIGIN), "already exists");
    }

    @Test
    void checkpointEncodingIsCanonical() throws IOException {
        Checkpoint checkpoint;
        try (TransparencyLog log = TransparencyLog.create(directory, ORIGIN)) {
            log.append(bytes("a"));
            checkpoint = log.checkpoint();
        }
        String encoded = checkpoint.encode();

        assertThrows(IllegalArgumentException.class, () -> Checkpoint.parse(encoded.replace("size: 1", "size: 01")));
        assertThrows(IllegalArgumentException.class, () -> Checkpoint.parse(encoded.replace("size: 1", "size: +1")));
        assertThrows(IllegalArgumentException.class, () -> Checkpoint.parse(encoded + "\n"));
        assertThrows(IllegalArgumentException.class, () -> Checkpoint.parse(encoded.replace("\n", "\r\n")));
        assertThrows(IllegalArgumentException.class, () -> Checkpoint.parse(encoded.replace("origin: ", "origin:  ")));
        assertThrows(IllegalArgumentException.class, () -> Checkpoint.parse(""));

        // Changing any signed field invalidates the signature.
        Checkpoint altered = Checkpoint.parse(encoded.replace("size: 1", "size: 2"));
        assertFalse(altered.verify(Keys.decodePublic(Files.readString(directory.resolve("log.pub")))));
    }

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
