package dev.waxseal.merkle;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import org.junit.jupiter.api.Test;

class MerkleTreeTest {

    private static final HexFormat HEX = HexFormat.of();
    private static final int SIZES = 70;

    /** Leaves and expected roots from the Certificate Transparency (RFC 6962) reference test suite. */
    private static final String[] REFERENCE_LEAVES = {
        "", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f",
    };
    private static final String[] REFERENCE_ROOTS = {
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    };

    @Test
    void emptyTreeHashesToTheEmptyString() {
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                HEX.formatHex(new MerkleTree().root()));
    }

    @Test
    void matchesCertificateTransparencyReferenceRoots() {
        MerkleTree tree = new MerkleTree();
        for (int i = 0; i < REFERENCE_LEAVES.length; i++) {
            tree.append(HEX.parseHex(REFERENCE_LEAVES[i]));
            assertEquals(REFERENCE_ROOTS[i], HEX.formatHex(tree.root()), "root after " + (i + 1) + " leaves");
        }
        for (int size = 1; size <= REFERENCE_LEAVES.length; size++) {
            assertEquals(REFERENCE_ROOTS[size - 1], HEX.formatHex(tree.rootAt(size)), "historical root at " + size);
        }
    }

    @Test
    void storedSubtreesAgreeWithTheNaiveRecursiveDefinition() {
        List<byte[]> entries = new ArrayList<>();
        MerkleTree tree = new MerkleTree();
        for (int i = 0; i < 130; i++) {
            entries.add(entry(i));
            tree.append(entry(i));
            assertArrayEquals(naiveRoot(entries), tree.root(), "size " + (i + 1));
        }
    }

    @Test
    void everyInclusionProofVerifiesForEveryHistoricalSize() {
        MerkleTree tree = treeOf(SIZES);
        for (int size = 1; size <= SIZES; size++) {
            byte[] root = tree.rootAt(size);
            for (int index = 0; index < size; index++) {
                List<byte[]> path = tree.inclusionProof(index, size);
                assertTrue(ProofVerifier.verifyInclusion(index, size, Hashing.leafHash(entry(index)), path, root),
                        "index " + index + " in size " + size);
                assertTrue(path.size() <= 64 - Long.numberOfLeadingZeros(Math.max(1, size - 1)),
                        "path is logarithmic for index " + index + " in size " + size);
            }
        }
    }

    @Test
    void inclusionProofIsBoundToEntryPositionAndRoot() {
        MerkleTree tree = treeOf(SIZES);
        for (int size = 2; size <= SIZES; size++) {
            byte[] root = tree.rootAt(size);
            int index = size / 2;
            List<byte[]> path = tree.inclusionProof(index, size);
            byte[] leaf = Hashing.leafHash(entry(index));

            assertFalse(ProofVerifier.verifyInclusion(index, size, Hashing.leafHash(entry(index + 1)), path, root),
                    "different entry, size " + size);
            assertFalse(ProofVerifier.verifyInclusion(index - 1, size, leaf, path, root),
                    "different position, size " + size);
            assertFalse(ProofVerifier.verifyInclusion(index, size, leaf, path, tree.rootAt(size - 1)),
                    "different root, size " + size);
            assertFalse(ProofVerifier.verifyInclusion(index, size, leaf, flipBit(path, 0), root),
                    "tampered path, size " + size);
            assertFalse(ProofVerifier.verifyInclusion(index, size, leaf, path.subList(1, path.size()), root),
                    "truncated path, size " + size);
            assertFalse(ProofVerifier.verifyInclusion(size, size, leaf, path, root), "index beyond the tree");
        }
    }

    @Test
    void leafCannotBePassedOffAsAnInteriorNode() {
        // Without the 0x00/0x01 prefixes, a two-leaf tree and the single "leaf" made of its two
        // child hashes would share a root. Domain separation keeps them apart.
        MerkleTree two = treeOf(2);
        byte[] concatenated = new byte[2 * Hashing.HASH_LENGTH];
        System.arraycopy(Hashing.leafHash(entry(0)), 0, concatenated, 0, Hashing.HASH_LENGTH);
        System.arraycopy(Hashing.leafHash(entry(1)), 0, concatenated, Hashing.HASH_LENGTH, Hashing.HASH_LENGTH);
        MerkleTree one = new MerkleTree();
        one.append(concatenated);
        assertFalse(java.util.Arrays.equals(two.root(), one.root()));
    }

    @Test
    void everyConsistencyProofVerifies() {
        MerkleTree tree = treeOf(SIZES);
        for (int second = 0; second <= SIZES; second++) {
            for (int first = 0; first <= second; first++) {
                List<byte[]> proof = tree.consistencyProof(first, second);
                assertTrue(ProofVerifier.verifyConsistency(first, second, tree.rootAt(first), tree.rootAt(second),
                        proof), first + " -> " + second);
            }
        }
    }

    @Test
    void consistencyProofExposesRewrittenHistory() {
        MerkleTree honest = treeOf(SIZES);
        for (int changed = 0; changed < 12; changed++) {
            MerkleTree rewritten = new MerkleTree();
            for (int i = 0; i < SIZES; i++) {
                rewritten.append(i == changed ? "forged".getBytes(StandardCharsets.UTF_8) : entry(i));
            }
            for (int first = changed + 1; first < SIZES; first += 3) {
                for (int second = first + 1; second <= SIZES; second += 5) {
                    // The rewritten log's best effort: its own, internally valid proof.
                    List<byte[]> proof = rewritten.consistencyProof(first, second);
                    assertTrue(ProofVerifier.verifyConsistency(first, second, rewritten.rootAt(first),
                            rewritten.rootAt(second), proof), "sanity: proof is valid for the rewritten log");
                    assertFalse(ProofVerifier.verifyConsistency(first, second, honest.rootAt(first),
                            rewritten.rootAt(second), proof),
                            "entry " + changed + " rewritten, " + first + " -> " + second);
                    // Nor does the honest log's proof help the rewritten root.
                    assertFalse(ProofVerifier.verifyConsistency(first, second, honest.rootAt(first),
                            rewritten.rootAt(second), honest.consistencyProof(first, second)));
                }
            }
        }
    }

    @Test
    void consistencyProofRejectsTamperedTruncatedAndPaddedProofs() {
        MerkleTree tree = treeOf(SIZES);
        for (int first = 1; first < SIZES; first += 2) {
            for (int second = first + 1; second <= SIZES; second += 3) {
                byte[] firstRoot = tree.rootAt(first);
                byte[] secondRoot = tree.rootAt(second);
                List<byte[]> proof = tree.consistencyProof(first, second);
                String label = first + " -> " + second;

                assertFalse(ProofVerifier.verifyConsistency(first, second, firstRoot, secondRoot,
                        flipBit(proof, proof.size() - 1)), "tampered " + label);
                assertFalse(ProofVerifier.verifyConsistency(first, second, firstRoot, secondRoot,
                        proof.subList(0, proof.size() - 1)), "truncated " + label);
                List<byte[]> padded = new ArrayList<>(proof);
                padded.add(new byte[Hashing.HASH_LENGTH]);
                assertFalse(ProofVerifier.verifyConsistency(first, second, firstRoot, secondRoot, padded),
                        "padded " + label);
                assertFalse(ProofVerifier.verifyConsistency(second, first, secondRoot, firstRoot, proof),
                        "reversed " + label);
            }
        }
    }

    @Test
    void verifierRejectsMalformedInputInsteadOfThrowing() {
        MerkleTree tree = treeOf(8);
        byte[] root = tree.root();
        List<byte[]> shortHash = List.of(new byte[5]);
        assertFalse(ProofVerifier.verifyInclusion(0, 8, Hashing.leafHash(entry(0)), shortHash, root));
        assertFalse(ProofVerifier.verifyInclusion(-1, 8, Hashing.leafHash(entry(0)), List.of(), root));
        assertFalse(ProofVerifier.verifyInclusion(0, 8, new byte[3], tree.inclusionProof(0, 8), root));
        assertFalse(ProofVerifier.verifyConsistency(3, 8, tree.rootAt(3), root, shortHash));
        assertFalse(ProofVerifier.verifyConsistency(3, 8, tree.rootAt(3), root, null));
        assertFalse(ProofVerifier.verifyConsistency(4, 8, tree.rootAt(4), root, List.of()));
    }

    @Test
    void rejectsRequestsOutsideTheTree() {
        MerkleTree tree = treeOf(5);
        assertThrows(IllegalArgumentException.class, () -> tree.rootAt(6));
        assertThrows(IllegalArgumentException.class, () -> tree.inclusionProof(5, 5));
        assertThrows(IllegalArgumentException.class, () -> tree.inclusionProof(0, 6));
        assertThrows(IllegalArgumentException.class, () -> tree.consistencyProof(4, 3));
        assertThrows(IllegalArgumentException.class, () -> tree.consistencyProof(-1, 3));
    }

    @Test
    void returnedHashesAreCopies() {
        MerkleTree tree = treeOf(4);
        byte[] before = tree.root();
        tree.root()[0] ^= 1;
        tree.inclusionProof(0, 4).get(0)[0] ^= 1;
        assertArrayEquals(before, tree.root());
        assertTrue(ProofVerifier.verifyInclusion(0, 4, Hashing.leafHash(entry(0)), tree.inclusionProof(0, 4), before));
    }

    private static MerkleTree treeOf(int size) {
        MerkleTree tree = new MerkleTree();
        for (int i = 0; i < size; i++) {
            tree.append(entry(i));
        }
        return tree;
    }

    private static byte[] entry(int i) {
        return ("entry-" + i).getBytes(StandardCharsets.UTF_8);
    }

    private static List<byte[]> flipBit(List<byte[]> proof, int position) {
        List<byte[]> copy = new ArrayList<>();
        for (byte[] hash : proof) {
            copy.add(hash.clone());
        }
        copy.get(position)[7] ^= 0x10;
        return copy;
    }

    /** MTH from RFC 6962 written as literally as possible: no stored state, rehashes everything. */
    private static byte[] naiveRoot(List<byte[]> entries) {
        if (entries.isEmpty()) {
            return Hashing.emptyRoot();
        }
        if (entries.size() == 1) {
            return Hashing.leafHash(entries.get(0));
        }
        int k = 1;
        while (k * 2 < entries.size()) {
            k *= 2;
        }
        return Hashing.nodeHash(naiveRoot(entries.subList(0, k)), naiveRoot(entries.subList(k, entries.size())));
    }
}
