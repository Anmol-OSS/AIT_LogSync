"""Message bus between ingest and workers.

    memory  bounded in-process queue - single-process mode (`logsync serve`)
    kafka   Apache Kafka - ingest and workers as separate services; partitions are
            the scaling unit, at-least-once delivery (offsets committed only after a
            batch is stored), duplicates dropped by event id in the processor.

Topics: logsync.raw (every received event), logsync.dlq (unparsed and blocked
events, for triage - their raw bytes are archived and sealed regardless).
"""
import json
import queue
import threading
import time
from typing import Protocol

from ..core.processor import RawEvent

RAW_TOPIC = "logsync.raw"
DLQ_TOPIC = "logsync.dlq"


class Bus(Protocol):
    def publish(self, ev: RawEvent, block: bool = True) -> bool: ...
    def poll(self, max_items: int, timeout: float) -> list[RawEvent]: ...
    def commit(self) -> None: ...
    def dead_letter(self, event: dict) -> None: ...
    def close(self) -> None: ...


class MemoryBus:
    def __init__(self, maxsize: int = 50_000):
        self._q: queue.Queue[RawEvent] = queue.Queue(maxsize)
        self.dropped = 0
        self.dead_letters = 0

    def publish(self, ev: RawEvent, block: bool = True) -> bool:
        """block=True gives TCP backpressure; UDP publishes with block=False and counts drops."""
        try:
            self._q.put(ev, block=block, timeout=None if block else 0)
            return True
        except queue.Full:
            self.dropped += 1
            return False

    def poll(self, max_items: int = 512, timeout: float = 0.2) -> list[RawEvent]:
        out: list[RawEvent] = []
        try:
            out.append(self._q.get(timeout=timeout))
            while len(out) < max_items:
                out.append(self._q.get_nowait())
        except queue.Empty:
            pass
        return out

    def commit(self) -> None:
        pass

    def dead_letter(self, event: dict) -> None:
        self.dead_letters += 1

    def close(self) -> None:
        pass

    def qsize(self) -> int:
        return self._q.qsize()


class KafkaBus:
    """confluent-kafka producer/consumer. Message value = raw bytes (never re-encoded),
    key = source host (keeps a device's events ordered within a partition), metadata
    in headers."""

    def __init__(self, bootstrap: str, group: str = "logsync-workers", consume: bool = False):
        from confluent_kafka import Consumer, Producer
        self._producer = Producer({"bootstrap.servers": bootstrap, "linger.ms": 5,
                                   "enable.idempotence": True, "compression.type": "lz4"})
        self._consumer = None
        if consume:
            self._consumer = Consumer({"bootstrap.servers": bootstrap, "group.id": group,
                                       "enable.auto.commit": False, "auto.offset.reset": "earliest"})
            self._consumer.subscribe([RAW_TOPIC])
        self._lock = threading.Lock()
        self.dropped = 0

    def publish(self, ev: RawEvent, block: bool = True) -> bool:
        headers = [("event_id", ev.event_id.encode()), ("received_at", ev.received_at.encode()),
                   ("source_host", ev.source_host.encode())]
        while True:
            try:
                with self._lock:
                    self._producer.produce(RAW_TOPIC, value=ev.raw, key=ev.source_host.encode(), headers=headers)
                    self._producer.poll(0)
                return True
            except BufferError:          # local queue full: backpressure
                if not block:
                    self.dropped += 1
                    return False
                with self._lock:
                    self._producer.poll(0.1)

    def poll(self, max_items: int = 512, timeout: float = 0.5) -> list[RawEvent]:
        msgs = self._consumer.consume(num_messages=max_items, timeout=timeout)
        out = []
        for m in msgs:
            if m.error():
                continue
            h = {k: v.decode() for k, v in (m.headers() or [])}
            out.append(RawEvent(h.get("event_id", "kafka-%d-%d" % (m.partition(), m.offset())),
                                h.get("received_at", ""), h.get("source_host", "?"), m.value() or b""))
        return out

    def commit(self) -> None:
        if self._consumer is not None:
            try:
                self._consumer.commit(asynchronous=False)
            except Exception:  # nothing consumed yet
                pass

    def dead_letter(self, event: dict) -> None:
        meta = {"event_id": event["event_id"], "status": event["status"],
                "reason": event["roundtrip"].get("reason"), "archive_ref": event["raw"]["archive_ref"]}
        with self._lock:
            self._producer.produce(DLQ_TOPIC, value=event["raw"]["text"].encode("utf-8"),
                                   key=event["source"]["host"].encode(),
                                   headers=[("meta", json.dumps(meta).encode())])
            self._producer.poll(0)

    def flush(self, timeout: float = 10) -> None:
        with self._lock:
            self._producer.flush(timeout)

    def close(self) -> None:
        self.flush()
        if self._consumer is not None:
            self._consumer.close()


def wait_for_kafka(bootstrap: str, timeout: float = 60) -> None:
    from confluent_kafka.admin import AdminClient, NewTopic
    admin = AdminClient({"bootstrap.servers": bootstrap})
    deadline = time.monotonic() + timeout
    while True:
        try:
            admin.list_topics(timeout=5)
            break
        except Exception:
            if time.monotonic() > deadline:
                raise
            time.sleep(1)
    existing = admin.list_topics(timeout=5).topics
    new = [NewTopic(t, num_partitions=3, replication_factor=1) for t in (RAW_TOPIC, DLQ_TOPIC) if t not in existing]
    if new:
        for f in admin.create_topics(new).values():
            try:
                f.result()
            except Exception:
                pass  # created concurrently by another service
