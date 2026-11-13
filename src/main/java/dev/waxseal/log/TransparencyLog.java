package dev.waxseal.log;

import dev.waxseal.merkle.MerkleTree;
import java.io.Closeable;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.List;
import java.util.Optional;

/**
 * A tamper-evident, append-only log stored in a directory.
 *
 * <p>Entries are opaque bytes. Every entry becomes a leaf of a Merkle tree, and
 * {@link #checkpoint()} signs the current root. Opening a log replays the entries and compares
 * them with every checkpoint the log ever signed, so an edit, deletion, reordering or truncation
 * of checkpointed history is reported instead of silently accepted.
 */
public final class TransparencyLog implements Closeable {

    /** Largest entry accepted, so a single record cannot exhaust memory. */
    public static final int MAX_ENTRY_BYTES = 1 << 20;

    private static final String ENTRIES_FILE = "entries.dat";
    private static final String CHECKPOINTS_FILE = "checkpoints.txt";
    private static final String ORIGIN_FILE = "origin";
    private static final String PRIVATE_KEY_FILE = "log.key";
    private static final String PUBLIC_KEY_FILE = "log.pub";
    private static final String CHECKPOINT_SEPARATOR = "\n\n";

    private final Path directory;
    private final String origin;
    private final KeyPair keys;
    private final MerkleTree tree = new MerkleTree();
    private final EntryFile entries;
    private Checkpoint latest;

    private TransparencyLog(Path directory, String origin, KeyPair keys) throws IOException {
        this.directory = directory;
        this.origin = origin;
        this.keys = keys;
        this.entries = EntryFile.open(directory.resolve(ENTRIES_FILE), tree::append);
        try {
            verifyStoredCheckpoints();
            entries.discardTornTail();
        } catch (IOException | RuntimeException e) {
            entries.close();
            throw e;
        }
    }

    /** Creates a new log with a freshly generated signing key. */
    public static TransparencyLog create(Path directory, String origin) throws IOException {
        return create(directory, origin, Keys.generate());
    }

    /** Creates a new log that signs with the given key pair. */
    public static TransparencyLog create(Path directory, String origin, KeyPair keys) throws IOException {
        Files.createDirectories(directory);
        if (Files.exists(directory.resolve(ORIGIN_FILE))) {
            throw new IOException("a log already exists in " + directory);
        }
        // Validates the origin before anything is written.
        Checkpoint.sign(origin, 0, new MerkleTree().root(), 0, keys.getPrivate());

        Path privateKey = directory.resolve(PRIVATE_KEY_FILE);
        Files.writeString(privateKey, Keys.encodePrivate(keys.getPrivate()) + "\n", StandardOpenOption.CREATE_NEW);
        restrictToOwner(privateKey);
        Files.writeString(directory.resolve(PUBLIC_KEY_FILE), Keys.encodePublic(keys.getPublic()) + "\n",
                StandardOpenOption.CREATE_NEW);
        Files.writeString(directory.resolve(ORIGIN_FILE), origin + "\n", StandardOpenOption.CREATE_NEW);
        return new TransparencyLog(directory, origin, keys);
    }

    /**
     * Opens an existing log and verifies it against its own checkpoints.
     *
     * @throws TamperedLogException if checkpointed history was changed or removed
     * @throws CorruptLogException if the entry file is damaged
     */
    public static TransparencyLog open(Path directory) throws IOException {
        if (!Files.exists(directory.resolve(ORIGIN_FILE))) {
            throw new IOException("no log found in " + directory);
        }
        String origin = Files.readString(directory.resolve(ORIGIN_FILE)).strip();
        KeyPair keys = new KeyPair(
                Keys.decodePublic(Files.readString(directory.resolve(PUBLIC_KEY_FILE))),
                Keys.decodePrivate(Files.readString(directory.resolve(PRIVATE_KEY_FILE))));
        return new TransparencyLog(directory, origin, keys);
    }

    /** Durably appends an entry and returns its index. */
    public synchronized long append(byte[] entry) throws IOException {
        if (entry.length > MAX_ENTRY_BYTES) {
            throw new IllegalArgumentException("entry exceeds " + MAX_ENTRY_BYTES + " bytes");
        }
        long index = entries.append(entry);
        tree.append(entry);
        return index;
    }

    public synchronized byte[] entry(long index) throws IOException {
        return entries.read(index);
    }

    public synchronized long size() {
        return tree.size();
    }

    /**
     * Signs the current state of the log. Returns the previous checkpoint if nothing was appended
     * since, so the log never signs two different statements about the same size.
     */
    public synchronized Checkpoint checkpoint() throws IOException {
        if (latest != null && latest.treeSize() == tree.size()) {
            return latest;
        }
        Checkpoint checkpoint = Checkpoint.sign(origin, tree.size(), tree.root(), System.currentTimeMillis(),
                keys.getPrivate());
        Files.writeString(directory.resolve(CHECKPOINTS_FILE), checkpoint.encode() + "\n",
                StandardOpenOption.CREATE, StandardOpenOption.APPEND, StandardOpenOption.SYNC);
        latest = checkpoint;
        return checkpoint;
    }

    public synchronized Optional<Checkpoint> latestCheckpoint() {
        return Optional.ofNullable(latest);
    }

    public synchronized List<byte[]> inclusionProof(long index, long treeSize) {
        return tree.inclusionProof(index, treeSize);
    }

    public synchronized List<byte[]> consistencyProof(long first, long second) {
        return tree.consistencyProof(first, second);
    }

    public String origin() {
        return origin;
    }

    public PublicKey publicKey() {
        return keys.getPublic();
    }

    @Override
    public synchronized void close() throws IOException {
        entries.close();
    }

    private void verifyStoredCheckpoints() throws IOException {
        Path file = directory.resolve(CHECKPOINTS_FILE);
        if (!Files.exists(file)) {
            return;
        }
        String content = Files.readString(file);
        // Anything after the last separator is a checkpoint whose write was interrupted.
        int lastSeparator = content.lastIndexOf(CHECKPOINT_SEPARATOR);
        String complete = lastSeparator < 0 ? "" : content.substring(0, lastSeparator + CHECKPOINT_SEPARATOR.length());

        long intactUpTo = 0;
        for (String block : complete.split(CHECKPOINT_SEPARATOR)) {
            if (block.isEmpty()) {
                continue;
            }
            Checkpoint checkpoint = parseStored(block + "\n");
            if (checkpoint.treeSize() > tree.size()) {
                throw new TamperedLogException("log was truncated: a signed checkpoint covers "
                        + checkpoint.treeSize() + " entries but only " + tree.size() + " are stored");
            }
            if (!MessageDigest.isEqual(checkpoint.rootHash(), tree.rootAt(checkpoint.treeSize()))) {
                throw new TamperedLogException("entries in range [" + intactUpTo + ", " + checkpoint.treeSize()
                        + ") were modified: they no longer match the checkpoint signed at size "
                        + checkpoint.treeSize());
            }
            intactUpTo = checkpoint.treeSize();
            latest = checkpoint;
        }
        if (complete.length() != content.length()) {
            Files.writeString(file, complete, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.SYNC);
        }
    }

    private Checkpoint parseStored(String text) throws TamperedLogException {
        Checkpoint checkpoint;
        try {
            checkpoint = Checkpoint.parse(text);
        } catch (IllegalArgumentException e) {
            throw new TamperedLogException("a stored checkpoint is malformed");
        }
        if (!checkpoint.origin().equals(origin) || !checkpoint.verify(keys.getPublic())) {
            throw new TamperedLogException("a stored checkpoint was not signed by this log");
        }
        return checkpoint;
    }

    private static void restrictToOwner(Path file) {
        try {
            Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException e) {
            // Not a POSIX file system (for example NTFS): the directory's ACL is what protects the key.
        }
    }
}
