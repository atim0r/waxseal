package dev.waxseal.merkle;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Merkle tree hashing as defined by RFC 6962, section 2.1.
 *
 * <p>Leaves and interior nodes are hashed with different one-byte prefixes. Without that domain
 * separation an attacker could present the concatenation of two child hashes as if it were a leaf
 * and forge a proof (a second-preimage attack on the tree).
 */
public final class Hashing {

    public static final int HASH_LENGTH = 32;

    private static final byte LEAF_PREFIX = 0x00;
    private static final byte NODE_PREFIX = 0x01;

    private Hashing() {
    }

    public static byte[] leafHash(byte[] entry) {
        MessageDigest digest = sha256();
        digest.update(LEAF_PREFIX);
        return digest.digest(entry);
    }

    public static byte[] nodeHash(byte[] left, byte[] right) {
        MessageDigest digest = sha256();
        digest.update(NODE_PREFIX);
        digest.update(left);
        return digest.digest(right);
    }

    /** Root of the tree with no entries: the hash of the empty string. */
    public static byte[] emptyRoot() {
        return sha256().digest();
    }

    public static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by every Java runtime", e);
        }
    }
}
