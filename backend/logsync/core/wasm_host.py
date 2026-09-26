"""Run the pack tokenizer inside a Wasmtime sandbox.

The module (runtime/, Rust -> wasm32-unknown-unknown) has no imports, so it
cannot reach files, network, clock or randomness. Per call the host sets a
fuel budget (bounded CPU: a pathological line cannot hang the pipeline) and
the store caps linear memory. A trap - fuel exhausted, out of memory, panic -
never crashes the worker: the event is blocked with the reason, and a fresh
instance replaces the poisoned one.
"""
import json
import os
import threading
from pathlib import Path

import wasmtime

from .tokenize import TokenResult

DEFAULT_WASM = Path(__file__).with_name("wasm") / "logsync_runtime.wasm"
FUEL_PER_CALL = int(os.environ.get("LOGSYNC_WASM_FUEL", "20000000"))
MEMORY_LIMIT = int(os.environ.get("LOGSYNC_WASM_MEMORY", str(64 * 1024 * 1024)))
INIT_FUEL = 10_000_000  # instantiation and pack compilation; independent of the per-line budget
RS, US = "\x1e", "\x1f"


def encode_spec(spec: dict) -> bytes:
    """format RS header RS patterns RS columns RS delimiter (see runtime/src/lib.rs)."""
    return RS.join([spec["format"], spec.get("header", "") or "", US.join(spec.get("patterns", [])),
                    US.join(spec.get("columns", [])), spec.get("delimiter", "")]).encode("utf-8")


class WasmEngine:
    name = "wasm"

    def __init__(self, path: Path | None = None, fuel: int = FUEL_PER_CALL, memory_limit: int = MEMORY_LIMIT):
        self.path = Path(path or os.environ.get("LOGSYNC_WASM", DEFAULT_WASM))
        cfg = wasmtime.Config()
        cfg.consume_fuel = True
        self._engine = wasmtime.Engine(cfg)
        self._module = wasmtime.Module.from_file(self._engine, str(self.path))
        if self._module.imports:
            raise RuntimeError("sandbox violation: WASM module imports %s"
                               % [i.name for i in self._module.imports])
        self.fuel, self.memory_limit = fuel, memory_limit
        self.traps = 0
        self._lock = threading.Lock()
        self._instantiate()

    @property
    def imports(self) -> list:
        return list(self._module.imports)

    def _instantiate(self) -> None:
        self._store = wasmtime.Store(self._engine)
        self._store.set_limits(memory_size=self.memory_limit)
        self._store.set_fuel(INIT_FUEL)                # a new store has no fuel, even for start-up
        inst = wasmtime.Instance(self._store, self._module, [])
        ex = inst.exports(self._store)
        self._mem, self._alloc, self._free = ex["memory"], ex["ls_alloc"], ex["ls_free"]
        self._load, self._tok, self._tok_batch = ex["ls_load"], ex["ls_tokenize"], ex["ls_tokenize_batch"]
        self._handles: dict[bytes, int] = {}

    def _put(self, data: bytes) -> int:
        ptr = self._alloc(self._store, len(data))
        self._mem.write(self._store, data, ptr)
        return ptr

    def _handle(self, spec: dict) -> int:
        key = encode_spec(spec)
        h = self._handles.get(key)
        if h is None:
            self._store.set_fuel(INIT_FUEL)            # regex compilation is costlier than a parse
            ptr = self._put(key)
            h = self._load(self._store, ptr, len(key))
            self._free(self._store, ptr, len(key))
            if h < 0:
                raise ValueError("WASM runtime rejected pack spec")
            self._handles[key] = h
        return h

    def tokenize(self, spec: dict, raw: bytes) -> TokenResult:
        with self._lock:
            try:
                h = self._handle(spec)
                self._store.set_fuel(self.fuel)
                ptr = self._put(raw) if raw else self._alloc(self._store, 0)
                packed = self._tok(self._store, h, ptr, len(raw))
                self._free(self._store, ptr, len(raw))
                rptr, rlen = packed >> 32, packed & 0xFFFFFFFF
                out = json.loads(self._mem.read(self._store, rptr, rptr + rlen))
                self._free(self._store, rptr, rlen)
            except wasmtime.Trap as trap:
                self.traps += 1
                self._instantiate()                    # never reuse a trapped instance
                msg = str(trap)
                reason = ("parser exceeded its CPU budget (fuel)" if "fuel" in msg
                          else "parser trapped: %s" % msg.strip().splitlines()[-1])
                return TokenResult(False, error=reason)
            except wasmtime.WasmtimeError as err:
                self.traps += 1
                self._instantiate()
                return TokenResult(False, error="sandbox error: %s" % str(err).splitlines()[0])
        return TokenResult(out["ok"], out["fields"], out["unexplained"], out["error"])

    def tokenize_many(self, spec: dict, raws: list[bytes]) -> list[TokenResult]:
        """One sandbox crossing for many lines (the per-call overhead dominates a
        single short line). Fuel scales with the batch; if the batch traps, the
        lines are retried one by one so only the offending line is blocked."""
        if not raws:
            return []
        buf = b"".join(len(r).to_bytes(4, "little") + r for r in raws)
        with self._lock:
            try:
                h = self._handle(spec)
                self._store.set_fuel(self.fuel * len(raws))
                ptr = self._put(buf)
                packed = self._tok_batch(self._store, h, ptr, len(buf))
                self._free(self._store, ptr, len(buf))
                rptr, rlen = packed >> 32, packed & 0xFFFFFFFF
                out = json.loads(self._mem.read(self._store, rptr, rptr + rlen))
                self._free(self._store, rptr, rlen)
            except (wasmtime.Trap, wasmtime.WasmtimeError):
                self.traps += 1
                self._instantiate()
                out = None
        if out is None:
            return [self.tokenize(spec, r) for r in raws]
        return [TokenResult(o["ok"], o["fields"], o["unexplained"], o["error"]) for o in out]

    def fuel_used(self, spec: dict, raw: bytes) -> int:
        """Fuel one call consumes (for sizing the budget)."""
        with self._lock:
            self._handle(spec)
        self.tokenize(spec, raw)
        with self._lock:
            return self.fuel - self._store.get_fuel()
