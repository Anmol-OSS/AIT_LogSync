"""Append-only Merkle log, RFC 6962 (Certificate Transparency) hashing.

    leaf hash  = SHA-256(0x00 || data)
    node hash  = SHA-256(0x01 || left || right)
    MTH(D[n])  = split at k, the largest power of two < n

Inclusion proofs follow RFC 6962 section 2.1.1 and are verified with the
algorithm in RFC 9162 section 2.1.3.2. This is a transparency log built on
published standards, not a blockchain.
"""
import hashlib
import os
from pathlib import Path

HASH_LEN = 32
EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def verify_inclusion(leaf: bytes, index: int, size: int, proof: list[bytes], root: bytes) -> bool:
    """RFC 9162 2.1.3.2: does `proof` show leaf hash `leaf` at `index` in the tree of `size`?"""
    if index >= size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


class MerkleTree:
    """In-memory tree over leaf hashes. levels[h][i] is the hash of the perfect
    subtree covering leaves [i*2^h, (i+1)*2^h) - computed once, never changes."""

    def __init__(self, leaves: list[bytes] | None = None):
        self.levels: list[list[bytes]] = [[]]
        for lh in leaves or []:
            self.append(lh)

    @property
    def size(self) -> int:
        return len(self.levels[0])

    def append(self, lh: bytes) -> int:
        """Add a leaf hash; returns its index."""
        self.levels[0].append(lh)
        h = 0
        while len(self.levels[h]) % 2 == 0:
            if h + 1 == len(self.levels):
                self.levels.append([])
            lvl = self.levels[h]
            self.levels[h + 1].append(node_hash(lvl[-2], lvl[-1]))
            h += 1
        return self.size - 1

    def _subtree(self, start: int, n: int) -> bytes:
        """MTH of leaves [start, start+n)."""
        if n & (n - 1) == 0:  # perfect subtree: start is always aligned to n here
            return self.levels[n.bit_length() - 1][start // n]
        k = _split(n)
        return node_hash(self._subtree(start, k), self._subtree(start + k, n - k))

    def root(self, size: int | None = None) -> bytes:
        n = self.size if size is None else size
        if n > self.size:
            raise ValueError("tree has only %d leaves" % self.size)
        return EMPTY_ROOT if n == 0 else self._subtree(0, n)

    def inclusion_proof(self, index: int, size: int | None = None) -> list[bytes]:
        """RFC 6962 PATH(index, D[0:size])."""
        n = self.size if size is None else size
        if not 0 <= index < n <= self.size:
            raise ValueError("index %d not in tree of size %d" % (index, n))
        proof: list[bytes] = []
        start = 0
        while n > 1:
            k = _split(n)
            if index < k:  # leaf is on the left: prove with the right subtree
                proof.append(self._subtree(start + k, n - k))
                n = k
            else:
                proof.append(self._subtree(start, k))
                start, index, n = start + k, index - k, n - k
        return list(reversed(proof))


class MerkleLog(MerkleTree):
    """MerkleTree persisted as a flat file of 32-byte leaf hashes (append-only).

    One process writes (the pipeline worker); readers call refresh() to pick
    up leaves appended by the writer since they last looked."""

    def __init__(self, path: Path):
        super().__init__()
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._offset = 0
        self.refresh()

    def refresh(self) -> None:
        with open(self.path, "rb") as f:
            f.seek(self._offset)
            data = f.read()
        usable = len(data) - len(data) % HASH_LEN  # ignore a half-written trailing leaf
        for i in range(0, usable, HASH_LEN):
            super().append(data[i:i + HASH_LEN])
        self._offset += usable

    def append(self, lh: bytes) -> int:
        return self.append_many([lh])[0]

    def append_many(self, hashes: list[bytes]) -> list[int]:
        """Append a batch of leaves with a single fsync."""
        if not hashes:
            return []
        with open(self.path, "ab") as f:
            f.write(b"".join(hashes))
            f.flush()
            os.fsync(f.fileno())
        self._offset += HASH_LEN * len(hashes)
        return [super(MerkleLog, self).append(h) for h in hashes]
