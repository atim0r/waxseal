package dev.waxseal.merkle;

import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * Verifies Merkle proofs without access to the log, using the iterative algorithms of RFC 9162
 * (sections 2.1.3.2 and 2.1.4.2).
 *
 * <p>This is the code a client or auditor runs. It deliberately shares nothing with
 * {@link MerkleTree} except the hash function: proofs are generated from the recursive definition
 * and checked by an independently specified algorithm, so one cannot hide a bug in the other.
 */
public final class ProofVerifier {

    private ProofVerifier() {
    }

    /** True if {@code path} proves that {@code leafHash} is entry {@code leafIndex} of the tree. */
    public static boolean verifyInclusion(long leafIndex, long treeSize, byte[] leafHash,
                                          List<byte[]> path, byte[] root) {
        if (leafIndex < 0 || leafIndex >= treeSize || !wellFormed(path) || !isHash(leafHash)) {
            return false;
        }
        long fn = leafIndex;
        long sn = treeSize - 1;
        byte[] r = leafHash;
        for (byte[] p : path) {
            if (sn == 0) {
                return false;
            }
            if ((fn & 1) == 1 || fn == sn) {
                r = Hashing.nodeHash(p, r);
                while ((fn & 1) == 0 && fn != 0) {
                    fn >>>= 1;
                    sn >>>= 1;
                }
            } else {
                r = Hashing.nodeHash(r, p);
            }
            fn >>>= 1;
            sn >>>= 1;
        }
        return sn == 0 && MessageDigest.isEqual(r, root);
    }

    /**
     * True if {@code proof} shows that the tree with {@code secondRoot} contains, unchanged and in
     * the same order, every entry of the earlier tree with {@code firstRoot}.
     */
    public static boolean verifyConsistency(long first, long second, byte[] firstRoot, byte[] secondRoot,
                                            List<byte[]> proof) {
        if (first < 0 || first > second || !wellFormed(proof) || !isHash(firstRoot) || !isHash(secondRoot)) {
            return false;
        }
        if (first == second) {
            return proof.isEmpty() && MessageDigest.isEqual(firstRoot, secondRoot);
        }
        if (first == 0) {
            // Every tree extends the empty tree; there is nothing to prove.
            return proof.isEmpty() && MessageDigest.isEqual(firstRoot, Hashing.emptyRoot());
        }
        List<byte[]> path = new ArrayList<>(proof);
        if (Long.bitCount(first) == 1) {
            // The old tree is a complete subtree of the new one, so its root is the starting node.
            path.add(0, firstRoot);
        }
        if (path.isEmpty()) {
            return false;
        }
        long fn = first - 1;
        long sn = second - 1;
        while ((fn & 1) == 1) {
            fn >>>= 1;
            sn >>>= 1;
        }
        byte[] fr = path.get(0);
        byte[] sr = path.get(0);
        for (byte[] c : path.subList(1, path.size())) {
            if (sn == 0) {
                return false;
            }
            if ((fn & 1) == 1 || fn == sn) {
                fr = Hashing.nodeHash(c, fr);
                sr = Hashing.nodeHash(c, sr);
                while ((fn & 1) == 0 && fn != 0) {
                    fn >>>= 1;
                    sn >>>= 1;
                }
            } else {
                sr = Hashing.nodeHash(sr, c);
            }
            fn >>>= 1;
            sn >>>= 1;
        }
        return sn == 0 && MessageDigest.isEqual(fr, firstRoot) && MessageDigest.isEqual(sr, secondRoot);
    }

    private static boolean wellFormed(List<byte[]> path) {
        if (path == null || path.size() > Long.SIZE) {
            return false;
        }
        for (byte[] hash : path) {
            if (!isHash(hash)) {
                return false;
            }
        }
        return true;
    }

    private static boolean isHash(byte[] value) {
        return value != null && value.length == Hashing.HASH_LENGTH;
    }
}
