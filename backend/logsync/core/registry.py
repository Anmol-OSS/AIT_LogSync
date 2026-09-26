"""Pack registry: signed, versioned parser packs with hot reload.

Runtime packs live in data/packs as  <id>@<version>.yaml  plus a detached
Ed25519 signature  <id>@<version>.yaml.sig. Only packs whose signature
verifies are loaded. Old versions are kept so events parsed by them stay
verifiable; the highest version of each id is the one used for new events.

On first start the built-in packs shipped in packs/ are copied in and signed
with the operator's pack key (trust on first use).
"""
import logging
import threading
from pathlib import Path

from ..storage.keys import Signer
from .pack import Pack, PackError, load_pack

log = logging.getLogger("logsync.registry")


def _version_key(v: str):
    return tuple(int(p) if p.isdigit() else 0 for p in v.split("."))


class Registry:
    def __init__(self, directory: Path, signer: Signer):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.signer = signer
        self._lock = threading.Lock()
        self._all: dict[str, Pack] = {}      # "id@version" -> Pack
        self._active: list[Pack] = []        # newest version per id, identify order
        self._stamp = None
        self.rejected: dict[str, str] = {}   # file -> reason (bad signature, invalid pack)

    # ---------------------------------------------------------------- setup
    def bootstrap(self, builtin_dir: Path) -> int:
        """Copy and sign built-in packs that are not in the registry yet."""
        added = 0
        for path in sorted(Path(builtin_dir).glob("*.yaml")):
            pack = load_pack(path.read_bytes().decode("utf-8"))
            if not (self.dir / ("%s.yaml" % pack.ref)).exists():
                self.add(pack.text, reload=False)
                added += 1
        self.reload()
        return added

    def add(self, text: str, reload: bool = True) -> Pack:
        """Validate, sign and store a pack. Raises PackError if invalid or version exists."""
        pack = load_pack(text)
        target = self.dir / ("%s.yaml" % pack.ref)
        if target.exists():
            raise PackError("%s already exists - bump the version" % pack.ref)
        data = text.encode("utf-8")
        target.with_suffix(".yaml.sig").write_text(self.signer.sign(data) + "\n")
        target.write_bytes(data)
        if reload:
            self.reload()
        return pack

    # ---------------------------------------------------------------- hot reload
    def _listing(self):
        return tuple(sorted((p.name, p.stat().st_mtime_ns) for p in self.dir.glob("*.yaml*")))

    def reload_if_changed(self) -> bool:
        if self._listing() != self._stamp:
            self.reload()
            return True
        return False

    def reload(self) -> None:
        stamp = self._listing()
        packs: dict[str, Pack] = {}
        rejected: dict[str, str] = {}
        for path in sorted(self.dir.glob("*.yaml")):
            data = path.read_bytes()
            sig = path.with_suffix(".yaml.sig")
            if not sig.exists() or not self.signer.verify(data, sig.read_text().strip()):
                rejected[path.name] = "missing or invalid signature"
                continue
            try:
                pack = load_pack(data.decode("utf-8"))
            except PackError as e:
                rejected[path.name] = str(e)
                continue
            packs[pack.ref] = pack
        newest: dict[str, Pack] = {}
        for p in packs.values():
            if p.id not in newest or _version_key(p.version) > _version_key(newest[p.id].version):
                newest[p.id] = p
        with self._lock:
            self._all = packs
            self._active = sorted(newest.values(), key=lambda p: (p.priority, p.id))
            self._stamp = stamp
            self.rejected = rejected
        for name, why in rejected.items():
            log.warning("pack %s rejected: %s", name, why)

    # ---------------------------------------------------------------- lookup
    def identify(self, raw: bytes) -> Pack | None:
        head = raw[:1024]
        with self._lock:
            active = self._active
        for pack in active:
            if pack.fingerprint.search(head):
                return pack
        return None

    def get(self, pack_id: str, version: str) -> Pack | None:
        with self._lock:
            return self._all.get("%s@%s" % (pack_id, version))

    def active(self) -> list[Pack]:
        with self._lock:
            return list(self._active)

    def is_signed(self, pack: Pack) -> bool:
        sig = self.dir / ("%s.yaml.sig" % pack.ref)
        return sig.exists() and self.signer.verify(pack.text.encode("utf-8"), sig.read_text().strip())
