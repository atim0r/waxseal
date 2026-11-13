package dev.waxseal.witness;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.waxseal.log.Checkpoint;
import dev.waxseal.log.Keys;
import dev.waxseal.log.TransparencyLog;
import dev.waxseal.witness.MisbehaviorException.Reason;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class WitnessTest {

    private static final String ORIGIN = "test.waxseal";

    @TempDir
    Path directory;

    private final KeyPair keys = Keys.generate();
    private TransparencyLog log;
    private Witness witness;
    private Path stateFile;

    @BeforeEach
    void setUp() throws IOException {
        log = TransparencyLog.create(directory.resolve("log"), ORIGIN, keys);
        stateFile = directory.resolve("witness-checkpoint");
        witness = new Witness(keys.getPublic(), stateFile);
    }

    @AfterEach
    void tearDown() throws IOException {
        log.close();
    }

    @Test
    void followsAnHonestLogAsItGrows() throws Exception {
        long trusted = 0;
        for (int round = 1; round <= 20; round++) {
            for (int i = 0; i < round; i++) {
                log.append(bytes("round " + round + " event " + i));
            }
            Checkpoint next = log.checkpoint();
            witness.advance(next, trusted == 0 ? List.of() : log.consistencyProof(trusted, next.treeSize()));
            trusted = next.treeSize();
            assertEquals(next, witness.trusted().orElseThrow());
        }
        assertEquals(210, trusted);
    }

    @Test
    void acceptsTheSameCheckpointAgain() throws Exception {
        log.append(bytes("a"));
        Checkpoint checkpoint = log.checkpoint();
        witness.advance(checkpoint, List.of());
        witness.advance(checkpoint, List.of());
        assertEquals(checkpoint, witness.trusted().orElseThrow());
    }

    @Test
    void rejectsACheckpointSignedByAnotherKey() throws Exception {
        log.append(bytes("a"));
        Checkpoint genuine = log.checkpoint();
        Checkpoint impostor = Checkpoint.sign(ORIGIN, genuine.treeSize(), genuine.rootHash(), 0,
                Keys.generate().getPrivate());

        assertReason(Reason.BAD_SIGNATURE, impostor, List.of());
        assertTrue(witness.trusted().isEmpty(), "nothing is trusted after a bad signature");
    }

    @Test
    void rejectsACheckpointFromAnotherLogSignedWithTheSameKey() throws Exception {
        log.append(bytes("a"));
        witness.advance(log.checkpoint(), List.of());

        try (TransparencyLog other = TransparencyLog.create(directory.resolve("other"), "other.waxseal", keys)) {
            other.append(bytes("a"));
            other.append(bytes("b"));
            assertReason(Reason.WRONG_ORIGIN, other.checkpoint(), other.consistencyProof(1, 2));
        }
    }

    @Test
    void rejectsARollback() throws Exception {
        log.append(bytes("a"));
        Checkpoint small = log.checkpoint();
        log.append(bytes("b"));
        Checkpoint large = log.checkpoint();
        witness.advance(large, List.of());

        assertReason(Reason.ROLLBACK, small, List.of());
        assertEquals(large, witness.trusted().orElseThrow());
    }

    @Test
    void rejectsTwoHistoriesOfTheSameSize() throws Exception {
        log.append(bytes("a"));
        log.append(bytes("b"));
        witness.advance(log.checkpoint(), List.of());

        try (TransparencyLog fork = TransparencyLog.create(directory.resolve("fork"), ORIGIN, keys)) {
            fork.append(bytes("a"));
            fork.append(bytes("something else"));
            assertReason(Reason.FORK, fork.checkpoint(), List.of());
        }
    }

    @Test
    void rejectsRewrittenHistoryEvenWhenSignedWithTheRealKey() throws Exception {
        for (int i = 0; i < 8; i++) {
            log.append(bytes("event " + i));
        }
        Checkpoint honest = log.checkpoint();
        witness.advance(honest, List.of());

        // The key holder rebuilds the log with entry 2 changed, extends it, and signs the result.
        try (TransparencyLog rewritten = TransparencyLog.create(directory.resolve("rewritten"), ORIGIN, keys)) {
            for (int i = 0; i < 12; i++) {
                rewritten.append(bytes(i == 2 ? "nothing to see here" : "event " + i));
            }
            Checkpoint forged = rewritten.checkpoint();
            assertTrue(forged.verify(keys.getPublic()), "the forged checkpoint carries a valid signature");

            assertReason(Reason.INCONSISTENT, forged, rewritten.consistencyProof(8, 12));
            assertReason(Reason.INCONSISTENT, forged, List.of());
        }
        // The honest log cannot vouch for the forged root either.
        for (int i = 8; i < 12; i++) {
            log.append(bytes("event " + i));
        }
        try (TransparencyLog rewritten = TransparencyLog.open(directory.resolve("rewritten"))) {
            assertReason(Reason.INCONSISTENT, rewritten.checkpoint(), log.consistencyProof(8, 12));
        }
        assertEquals(honest, witness.trusted().orElseThrow());
    }

    @Test
    void remembersWhatItTrustedAcrossRestarts() throws Exception {
        log.append(bytes("a"));
        log.append(bytes("b"));
        Checkpoint checkpoint = log.checkpoint();
        witness.advance(checkpoint, List.of());

        Witness restarted = new Witness(keys.getPublic(), stateFile);
        assertEquals(checkpoint, restarted.trusted().orElseThrow());

        // A restart must not reopen the trust-on-first-use window.
        try (TransparencyLog fork = TransparencyLog.create(directory.resolve("fork"), ORIGIN, keys)) {
            fork.append(bytes("x"));
            Checkpoint smaller = fork.checkpoint();
            MisbehaviorException error = assertThrows(MisbehaviorException.class,
                    () -> restarted.advance(smaller, List.of()));
            assertEquals(Reason.ROLLBACK, error.reason());
        }
    }

    @Test
    void refusesStateThatWasNotSignedByThePinnedKey() throws Exception {
        log.append(bytes("a"));
        Checkpoint foreign = Checkpoint.sign(ORIGIN, 1, log.checkpoint().rootHash(), 0, Keys.generate().getPrivate());
        Files.writeString(stateFile, foreign.encode());

        assertThrows(IOException.class, () -> new Witness(keys.getPublic(), stateFile));
    }

    @Test
    void checksInclusionAgainstTheTrustedCheckpoint() throws Exception {
        assertFalse(witness.verifyInclusion(bytes("a"), 0, List.of()), "nothing trusted yet");
        for (int i = 0; i < 5; i++) {
            log.append(bytes("event " + i));
        }
        witness.advance(log.checkpoint(), List.of());

        assertTrue(witness.verifyInclusion(bytes("event 3"), 3, log.inclusionProof(3, 5)));
        assertFalse(witness.verifyInclusion(bytes("event 3 (edited)"), 3, log.inclusionProof(3, 5)));
        assertFalse(witness.verifyInclusion(bytes("event 3"), 2, log.inclusionProof(3, 5)));
    }

    private void assertReason(Reason expected, Checkpoint checkpoint, List<byte[]> proof) {
        MisbehaviorException error = assertThrows(MisbehaviorException.class,
                () -> witness.advance(checkpoint, proof));
        assertEquals(expected, error.reason());
    }

    private static byte[] bytes(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }
}
