package dev.waxseal.log;

import dev.waxseal.merkle.Hashing;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.regex.Pattern;

/**
 * A signed statement by the log: "my first {@code treeSize} entries hash to {@code rootHash}".
 *
 * <p>Because the root commits to every entry and to their order, anyone holding a checkpoint can
 * later demand proof that the log still contains exactly that history.
 *
 * <p>The text encoding is canonical: a given checkpoint has exactly one valid encoding, and
 * {@link #parse} rejects everything else. That removes the classic signature pitfall where two
 * different byte strings are accepted as the same signed message.
 */
public final class Checkpoint {

    private static final String HEADER = "waxseal-checkpoint-v1";
    private static final Pattern ORIGIN = Pattern.compile("[A-Za-z0-9._/-]{1,128}");

    private final String origin;
    private final long treeSize;
    private final byte[] rootHash;
    private final long timestampMillis;
    private final byte[] signature;

    private Checkpoint(String origin, long treeSize, byte[] rootHash, long timestampMillis, byte[] signature) {
        if (origin == null || !ORIGIN.matcher(origin).matches()) {
            throw new IllegalArgumentException("origin must match " + ORIGIN.pattern());
        }
        if (treeSize < 0 || timestampMillis < 0) {
            throw new IllegalArgumentException("tree size and timestamp cannot be negative");
        }
        if (rootHash.length != Hashing.HASH_LENGTH) {
            throw new IllegalArgumentException("root hash must be " + Hashing.HASH_LENGTH + " bytes");
        }
        this.origin = origin;
        this.treeSize = treeSize;
        this.rootHash = rootHash.clone();
        this.timestampMillis = timestampMillis;
        this.signature = signature.clone();
    }

    public static Checkpoint sign(String origin, long treeSize, byte[] rootHash, long timestampMillis,
                                  PrivateKey key) {
        Checkpoint unsigned = new Checkpoint(origin, treeSize, rootHash, timestampMillis, new byte[0]);
        return new Checkpoint(origin, treeSize, rootHash, timestampMillis, Keys.sign(key, unsigned.signedBody()));
    }

    /** Parses the output of {@link #encode()}. The signature is not checked here; call {@link #verify}. */
    public static Checkpoint parse(String text) {
        String[] lines = text.split("\n", -1);
        if (lines.length != 7 || !lines[0].equals(HEADER) || !lines[6].isEmpty()) {
            throw new IllegalArgumentException("malformed checkpoint");
        }
        Checkpoint checkpoint = new Checkpoint(
                field(lines[1], "origin"),
                Long.parseLong(field(lines[2], "size")),
                Base64.getDecoder().decode(field(lines[3], "root")),
                Long.parseLong(field(lines[4], "time")),
                Base64.getDecoder().decode(field(lines[5], "sig")));
        if (!checkpoint.encode().equals(text)) {
            throw new IllegalArgumentException("checkpoint is not in canonical form");
        }
        return checkpoint;
    }

    public boolean verify(PublicKey key) {
        return Keys.verify(key, signedBody(), signature);
    }

    public String encode() {
        return body() + "sig: " + Base64.getEncoder().encodeToString(signature) + "\n";
    }

    public String origin() {
        return origin;
    }

    public long treeSize() {
        return treeSize;
    }

    public byte[] rootHash() {
        return rootHash.clone();
    }

    public long timestampMillis() {
        return timestampMillis;
    }

    private byte[] signedBody() {
        return body().getBytes(StandardCharsets.UTF_8);
    }

    private String body() {
        return HEADER + "\n"
                + "origin: " + origin + "\n"
                + "size: " + treeSize + "\n"
                + "root: " + Base64.getEncoder().encodeToString(rootHash) + "\n"
                + "time: " + timestampMillis + "\n";
    }

    private static String field(String line, String name) {
        String prefix = name + ": ";
        if (!line.startsWith(prefix)) {
            throw new IllegalArgumentException("malformed checkpoint: expected field '" + name + "'");
        }
        return line.substring(prefix.length());
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof Checkpoint that && encode().equals(that.encode());
    }

    @Override
    public int hashCode() {
        return encode().hashCode();
    }

    @Override
    public String toString() {
        return encode();
    }
}
