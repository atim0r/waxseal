package dev.waxseal.merkle;

import java.util.ArrayList;
import java.util.List;

/**
 * Append-only Merkle tree (RFC 6962) that can prove two things about any past size of itself:
 * that an entry is included, and that a later tree only appended to an earlier one.
 *
 * <p>The tree stores the hash of every <em>complete</em> subtree: {@code levels.get(h).get(i)} is
 * the hash of the perfect subtree covering leaves {@code [i * 2^h, (i + 1) * 2^h)}. Every perfect
 * subtree that the RFC's recursive definitions ever visit is aligned that way, so roots and proofs
 * for the current size or any earlier size cost O(log n) hashes instead of rehashing every entry.
 *
 * <p>Not thread-safe; callers synchronize.
 */
public final class MerkleTree {

    private final List<List<byte[]>> levels = new ArrayList<>();

    public long size() {
        return levels.isEmpty() ? 0 : levels.get(0).size();
    }

    /** Appends an entry and returns its index. */
    public long append(byte[] entry) {
        long index = size();
        byte[] node = Hashing.leafHash(entry);
        for (int level = 0; ; level++) {
            if (levels.size() == level) {
                levels.add(new ArrayList<>());
            }
            List<byte[]> row = levels.get(level);
            row.add(node);
            if (row.size() % 2 != 0) {
                return index;
            }
            // The node just added completes a pair, which completes a subtree one level up.
            node = Hashing.nodeHash(row.get(row.size() - 2), node);
        }
    }

    public byte[] root() {
        return rootAt(size());
    }

    /** Root hash the tree had when it contained only its first {@code treeSize} entries. */
    public byte[] rootAt(long treeSize) {
        checkTreeSize(treeSize);
        return treeSize == 0 ? Hashing.emptyRoot() : subtreeHash(0, treeSize).clone();
    }

    /** Audit path for entry {@code leafIndex} in the tree of the first {@code treeSize} entries. */
    public List<byte[]> inclusionProof(long leafIndex, long treeSize) {
        checkTreeSize(treeSize);
        if (leafIndex < 0 || leafIndex >= treeSize) {
            throw new IllegalArgumentException("leaf index out of range");
        }
        List<byte[]> path = new ArrayList<>();
        inclusionPath(leafIndex, 0, treeSize, path);
        return path;
    }

    /** Proof that the tree of size {@code second} is an append-only extension of size {@code first}. */
    public List<byte[]> consistencyProof(long first, long second) {
        checkTreeSize(second);
        if (first < 0 || first > second) {
            throw new IllegalArgumentException("first tree size out of range");
        }
        List<byte[]> path = new ArrayList<>();
        if (first != 0 && first != second) {
            consistencyPath(first, 0, second, true, path);
        }
        return path;
    }

    // PATH(m, D[n]) from RFC 6962, section 2.1.1, over the leaf range [begin, end).
    private void inclusionPath(long m, long begin, long end, List<byte[]> out) {
        long n = end - begin;
        if (n == 1) {
            return;
        }
        long k = splitPoint(n);
        if (m < k) {
            inclusionPath(m, begin, begin + k, out);
            out.add(subtreeHash(begin + k, end).clone());
        } else {
            inclusionPath(m - k, begin + k, end, out);
            out.add(subtreeHash(begin, begin + k).clone());
        }
    }

    // SUBPROOF(m, D[n], b) from RFC 6962, section 2.1.2, over the leaf range [begin, end).
    private void consistencyPath(long m, long begin, long end, boolean oldRootKnown, List<byte[]> out) {
        long n = end - begin;
        if (m == n) {
            if (!oldRootKnown) {
                out.add(subtreeHash(begin, end).clone());
            }
            return;
        }
        long k = splitPoint(n);
        if (m <= k) {
            consistencyPath(m, begin, begin + k, oldRootKnown, out);
            out.add(subtreeHash(begin + k, end).clone());
        } else {
            consistencyPath(m - k, begin + k, end, false, out);
            out.add(subtreeHash(begin, begin + k).clone());
        }
    }

    // MTH(D[begin:end]) from RFC 6962, section 2.1. Returns the stored array for perfect subtrees.
    private byte[] subtreeHash(long begin, long end) {
        long n = end - begin;
        if (Long.bitCount(n) == 1) {
            int level = Long.numberOfTrailingZeros(n);
            return levels.get(level).get((int) (begin >>> level));
        }
        long k = splitPoint(n);
        return Hashing.nodeHash(subtreeHash(begin, begin + k), subtreeHash(begin + k, end));
    }

    /** Largest power of two strictly smaller than {@code n}, for {@code n >= 2}. */
    private static long splitPoint(long n) {
        return Long.highestOneBit(n - 1);
    }

    private void checkTreeSize(long treeSize) {
        if (treeSize < 0 || treeSize > size()) {
            throw new IllegalArgumentException("tree size out of range");
        }
    }
}
