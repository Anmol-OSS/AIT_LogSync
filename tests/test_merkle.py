"""RFC 6962 Merkle tree: official test vectors, proofs, tamper detection."""
import pytest

from logsync.storage.merkle import (EMPTY_ROOT, MerkleLog, MerkleTree, leaf_hash, node_hash,
                                    verify_inclusion)

# Leaf inputs and roots from the Certificate Transparency reference test data
# (certificate-transparency-go merkle tests, derived from RFC 6962).
LEAVES = [bytes.fromhex(h) for h in [
    "", "00", "10", "2021", "3031", "40414243", "5051525354555657",
    "606162636465666768696a6b6c6d6e6f"]]
ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]


def reference_mth(hashes):
    """Direct transcription of the RFC 6962 recursive definition."""
    n = len(hashes)
    if n == 1:
        return hashes[0]
    k = 1
    while k * 2 < n:
        k *= 2
    return node_hash(reference_mth(hashes[:k]), reference_mth(hashes[k:]))


def test_empty_tree_root_is_sha256_of_empty_string():
    assert MerkleTree().root() == EMPTY_ROOT


@pytest.mark.parametrize("n", range(1, 9))
def test_rfc6962_reference_roots(n):
    tree = MerkleTree([leaf_hash(d) for d in LEAVES[:n]])
    assert tree.root().hex() == ROOTS[n - 1]


def test_historical_roots_stay_valid_as_tree_grows():
    tree = MerkleTree([leaf_hash(d) for d in LEAVES])
    for n in range(1, 9):
        assert tree.root(n).hex() == ROOTS[n - 1]


def test_matches_recursive_definition_for_many_sizes():
    hashes = [leaf_hash(b"event-%d" % i) for i in range(70)]
    tree = MerkleTree()
    for n, h in enumerate(hashes, 1):
        tree.append(h)
        assert tree.root() == reference_mth(hashes[:n])


def test_every_inclusion_proof_verifies_for_every_size():
    hashes = [leaf_hash(b"e%d" % i) for i in range(40)]
    tree = MerkleTree(hashes)
    for size in range(1, 41):
        root = tree.root(size)
        for i in range(size):
            proof = tree.inclusion_proof(i, size)
            assert verify_inclusion(hashes[i], i, size, proof, root), (i, size)


def test_tampered_leaf_or_wrong_index_fails():
    hashes = [leaf_hash(b"e%d" % i) for i in range(13)]
    tree = MerkleTree(hashes)
    root, proof = tree.root(), tree.inclusion_proof(5)
    assert verify_inclusion(hashes[5], 5, 13, proof, root)
    assert not verify_inclusion(leaf_hash(b"e5-altered"), 5, 13, proof, root)
    assert not verify_inclusion(hashes[5], 6, 13, proof, root)
    assert not verify_inclusion(hashes[5], 5, 13, proof[:-1], root)
    assert not verify_inclusion(hashes[5], 13, 13, proof, root)


def test_log_persists_and_reader_sees_writer_appends(tmp_path):
    path = tmp_path / "leaves.bin"
    writer = MerkleLog(path)
    for i in range(10):
        writer.append(leaf_hash(b"x%d" % i))
    reader = MerkleLog(path)
    assert reader.size == 10 and reader.root() == writer.root()
    writer.append(leaf_hash(b"x10"))
    reader.refresh()
    assert reader.size == 11 and reader.root() == writer.root()
