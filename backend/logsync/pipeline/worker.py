"""Pipeline worker: consume batches from the bus, process, commit, repeat."""
import logging
import threading
import time

from ..core.processor import Processor

log = logging.getLogger("logsync.worker")


class Worker:
    def __init__(self, processor: Processor, bus, batch_size: int = 512):
        self.processor, self.bus, self.batch_size = processor, bus, batch_size
        self.processed = 0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        # every unparsed/blocked event also goes to the dead-letter topic for triage
        processor.on_event = lambda e: bus.dead_letter(e) if e["status"] != "accepted" else None

    def run_once(self, timeout: float = 0.2) -> int:
        batch = self.bus.poll(self.batch_size, timeout)
        if batch:
            self.processor.process_batch(batch)
            self.bus.commit()            # only after the batch is durably stored
            self.processed += len(batch)
        return len(batch)

    def run(self) -> None:
        last_tick = 0.0
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                log.exception("batch failed; it will be redelivered (Kafka) or is lost (memory bus)")
                time.sleep(1)
            if time.monotonic() - last_tick >= 1.0:
                self.processor.tick()
                last_tick = time.monotonic()
        self.processor.flush()

    def start(self) -> "Worker":
        self._thread = threading.Thread(target=self.run, daemon=True, name="worker")
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
