package dev.waxseal.witness;

import dev.waxseal.log.Checkpoint;
import dev.waxseal.merkle.Hashing;
import dev.waxseal.merkle.ProofVerifier;
import dev.waxseal.witness.MisbehaviorException.Reason;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.List;
import java.util.Optional;

/**
 * An independent party that remembers the last checkpoint it saw and refuses to move to a new one
 * unless the log proves that the old history is still there, unchanged.
 *
 * <p>This is what makes the log tamper-evident against its own operator. A signature only shows
 * who wrote a checkpoint; someone who holds the signing key can rewrite the whole log and sign it
 * again. What they cannot do is produce a consistency proof linking the rewritten log to a
 * checkpoint a witness already holds.
 */
public final class Witness {

    private final PublicKey logKey;
    private final Path stateFile;
    private Checkpoint trusted;

    /** Loads the previously trusted checkpoint from {@code stateFile}, if there is one. */
    public Witness(PublicKey logKey, Path stateFile) throws IOException {
        this.logKey = logKey;
        this.stateFile = stateFile;
        if (Files.exists(stateFile)) {
            Checkpoint stored;
            try {
                stored = Checkpoint.parse(Files.readString(stateFile));
            } catch (IllegalArgumentException e) {
                throw new IOException("witness state in " + stateFile + " is unreadable", e);
            }
            if (!stored.verify(logKey)) {
                throw new IOException("witness state in " + stateFile + " is not signed by the pinned key");
            }
            this.trusted = stored;
        }
    }

    public synchronized Optional<Checkpoint> trusted() {
        return Optional.ofNullable(trusted);
    }

    /**
     * Accepts {@code next} as the new trusted checkpoint, or reports why an honest log could not
     * have produced it. The first checkpoint ever seen is trusted on first use.
     *
     * @param consistencyProof proof from the trusted size to the size of {@code next}; ignored
     *     when there is nothing to prove (first checkpoint, or an unchanged size)
     */
    public synchronized void advance(Checkpoint next, List<byte[]> consistencyProof)
            throws MisbehaviorException, IOException {
        if (!next.verify(logKey)) {
            throw new MisbehaviorException(Reason.BAD_SIGNATURE, "checkpoint is not signed by the pinned log key");
        }
        if (trusted == null) {
            save(next);
            return;
        }
        if (!next.origin().equals(trusted.origin())) {
            throw new MisbehaviorException(Reason.WRONG_ORIGIN,
                    "expected log '" + trusted.origin() + "' but got '" + next.origin() + "'");
        }
        if (next.treeSize() < trusted.treeSize()) {
            throw new MisbehaviorException(Reason.ROLLBACK, "log shrank from " + trusted.treeSize()
                    + " to " + next.treeSize() + " entries");
        }
        if (next.treeSize() == trusted.treeSize()) {
            if (!MessageDigest.isEqual(next.rootHash(), trusted.rootHash())) {
                throw new MisbehaviorException(Reason.FORK, "log signed two different histories of size "
                        + next.treeSize());
            }
            return;
        }
        if (!ProofVerifier.verifyConsistency(trusted.treeSize(), next.treeSize(), trusted.rootHash(),
                next.rootHash(), consistencyProof)) {
            throw new MisbehaviorException(Reason.INCONSISTENT, "the log of size " + next.treeSize()
                    + " does not contain the " + trusted.treeSize() + " entries it committed to earlier");
        }
        save(next);
    }

    /** True if {@code entry} is entry number {@code index} of the history this witness trusts. */
    public synchronized boolean verifyInclusion(byte[] entry, long index, List<byte[]> proof) {
        return trusted != null && ProofVerifier.verifyInclusion(index, trusted.treeSize(),
                Hashing.leafHash(entry), proof, trusted.rootHash());
    }

    private void save(Checkpoint checkpoint) throws IOException {
        // Write-then-rename, so a crash never leaves the witness with a half-written state.
        Path temporary = stateFile.resolveSibling(stateFile.getFileName() + ".tmp");
        Files.writeString(temporary, checkpoint.encode());
        try {
            Files.move(temporary, stateFile, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (java.nio.file.AtomicMoveNotSupportedException e) {
            Files.move(temporary, stateFile, StandardCopyOption.REPLACE_EXISTING);
        }
        trusted = checkpoint;
    }
}
