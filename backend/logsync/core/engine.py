"""Tokenizer engines. Both return a TokenResult for (compiled pack spec, raw bytes).

    python  reference implementation (core/tokenize.py)
    wasm    the same algorithms in Rust, compiled to WebAssembly and executed in
            a Wasmtime sandbox with fuel and memory limits (core/wasm_host.py)
"""
from typing import Protocol

from .tokenize import TokenResult, tokenize


class Engine(Protocol):
    name: str

    def tokenize(self, spec: dict, raw: bytes) -> TokenResult: ...


class PythonEngine:
    name = "python"

    def tokenize(self, spec: dict, raw: bytes) -> TokenResult:
        return tokenize(spec, raw)


def make_engine(kind: str) -> Engine:
    if kind == "python":
        return PythonEngine()
    if kind == "wasm":
        from .wasm_host import WasmEngine
        return WasmEngine()
    raise ValueError("unknown engine %r" % kind)
