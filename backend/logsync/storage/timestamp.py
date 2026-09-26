"""RFC 3161 trusted timestamps from a local, offline Time-Stamp Authority.

An air-gapped network cannot reach a public TSA, so the prototype runs its own
using the `openssl ts` command: a self-signed TSA certificate is created on
first use and each signed tree head is timestamped. `openssl ts -verify`
checks a token. If openssl is not installed, timestamping reports itself
unavailable instead of pretending.
"""
import hashlib
import shutil
import subprocess
import tempfile
from pathlib import Path

CONFIG = """
[ req ]
distinguished_name = dn
prompt = no
[ dn ]
CN = LogSync Local TSA
O = AIT_LogSync
[ tsa_ext ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,timeStamping
[ tsa ]
default_tsa = tsa_config
[ tsa_config ]
dir = {dir}
serial = $dir/serial
signer_cert = $dir/tsa.crt
signer_key = $dir/tsa.key
signer_digest = sha256
default_policy = 1.3.6.1.4.1.99999.1
digests = sha256
accuracy = secs:1
ordering = no
tsa_name = no
ess_cert_id_chain = no
ess_cert_id_alg = sha256
"""


class LocalTSA:
    def __init__(self, directory: Path, enabled: bool = True):
        self.dir = Path(directory)
        self.openssl = shutil.which("openssl") if enabled else None

    @property
    def available(self) -> bool:
        return self.openssl is not None

    def _run(self, *args: str, input: bytes | None = None) -> bytes:
        out = subprocess.run([self.openssl, *args], input=input, capture_output=True, timeout=30)
        if out.returncode != 0:
            raise RuntimeError(out.stderr.decode(errors="replace").strip())
        return out.stdout

    def _ensure(self) -> Path:
        cnf = self.dir / "tsa.cnf"
        if (self.dir / "tsa.crt").exists():
            return cnf
        self.dir.mkdir(parents=True, exist_ok=True)
        cnf.write_text(CONFIG.format(dir=self.dir.as_posix()), encoding="utf-8")
        (self.dir / "serial").write_text("01\n")
        self._run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                  "-days", "3650", "-keyout", str(self.dir / "tsa.key"), "-out", str(self.dir / "tsa.crt"),
                  "-config", str(cnf), "-extensions", "tsa_ext")
        return cnf

    def stamp(self, message: bytes) -> bytes | None:
        """Return a DER RFC 3161 TimeStampResp over SHA-256(message), or None if unavailable."""
        if not self.available:
            return None
        cnf = self._ensure()
        digest = hashlib.sha256(message).hexdigest()
        with tempfile.TemporaryDirectory() as tmp:
            req = Path(tmp) / "req.tsq"
            self._run("ts", "-query", "-digest", digest, "-sha256", "-cert", "-no_nonce", "-out", str(req))
            resp = Path(tmp) / "resp.tsr"
            self._run("ts", "-reply", "-config", str(cnf), "-queryfile", str(req), "-out", str(resp))
            return resp.read_bytes()

    def verify(self, message: bytes, token: bytes) -> bool:
        if not self.available or not token:
            return False
        with tempfile.TemporaryDirectory() as tmp:
            tsr = Path(tmp) / "resp.tsr"
            tsr.write_bytes(token)
            try:
                self._run("ts", "-verify", "-digest", hashlib.sha256(message).hexdigest(),
                          "-in", str(tsr), "-CAfile", str(self.dir / "tsa.crt"))
                return True
            except RuntimeError:
                return False

    def describe(self, token: bytes) -> str:
        """Human-readable 'Time stamp:' line from the token."""
        with tempfile.TemporaryDirectory() as tmp:
            tsr = Path(tmp) / "resp.tsr"
            tsr.write_bytes(token)
            text = self._run("ts", "-reply", "-in", str(tsr), "-text").decode(errors="replace")
        for line in text.splitlines():
            if line.startswith("Time stamp:"):
                return line.split(":", 1)[1].strip()
        return "?"
