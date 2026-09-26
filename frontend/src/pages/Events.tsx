import { useState } from "react";
import { Link, NavLink, useNavigate, useParams, useSearchParams } from "react-router";
import { getEvent, listEvents } from "../api";
import { RawLine } from "../components/RawLine";
import { ErrorNote, Loading, Pill, statusTone } from "../components/ui";
import { useAsync } from "../lib/useAsync";
import type { ByteRange, ProofCarryingEvent } from "../types";

const FILTERS = ["", "accepted", "blocked", "unparsed"];

export function Events() {
  const { id } = useParams();
  const [params, setParams] = useSearchParams();
  const status = params.get("status") ?? "";
  const { data: events, error } = useAsync(() => listEvents({ limit: 40, status: status || undefined }), [status], 5000);

  const selected = id ?? events?.[0]?.event_id;
  return (
    <>
      <h1>Event inspector</h1>
      <p className="muted">Can I prove where this field came from? Hover a field to see its exact source bytes.</p>
      <ErrorNote error={error} />
      <div className="filters">
        {FILTERS.map((f) => (
          <button key={f || "all"} className={f === status ? "chip active" : "chip"}
                  onClick={() => setParams(f ? { status: f } : {})}>{f || "all"}</button>
        ))}
      </div>
      <div className="split">
        <nav className="event-list">
          {!events ? <Loading /> : events.length === 0 ? <p className="muted">No events yet - start the replayer.</p> :
            events.map((e) => (
              <NavLink key={e.event_id} to={`/events/${e.event_id}${status ? `?status=${status}` : ""}`}
                       className={() => (e.event_id === selected ? "active" : "")}>
                <Pill tone={statusTone(e.status)}>{e.status}</Pill>
                <span>{e.source.family}</span>
                <code className="muted small">{e.event_id}</code>
              </NavLink>
            ))}
        </nav>
        {selected && <EventDetail id={selected} />}
      </div>
    </>
  );
}

function EventDetail({ id }: { id: string }) {
  const { data: event, error } = useAsync(() => getEvent(id), [id]);
  const [active, setActive] = useState<string | null>(null);
  const navigate = useNavigate();
  if (error) return <ErrorNote error={error} />;
  if (!event) return <Loading />;

  const highlights = event.provenance
    .filter((p) => p.bytes)
    .map((p) => ({ key: p.field, range: p.bytes as ByteRange }));

  return (
    <div className="detail">
      <section className="card">
        <div className="row-between">
          <h2>Raw event <span className="muted">· {event.source.family} · {event.source.format} · from {event.source.host}</span></h2>
          <Pill tone={statusTone(event.status)}>{event.status}</Pill>
        </div>
        {event.status === "accepted" ? (
          <RawLine text={event.raw.text} highlights={highlights} active={active} onHover={setActive} />
        ) : (
          <>
            <RawLine text={event.raw.text} tone="danger"
                     highlights={event.roundtrip.unexplained.map((r, i) => ({ key: `unexplained-${i}`, range: r }))} />
            <p className="text-bad">{event.status === "blocked"
              ? <>Round-trip gate: {event.roundtrip.reason}. The event was blocked instead of normalized with silent data loss.</>
              : <>Dead-letter: {event.roundtrip.reason}.</>} Its raw bytes are still archived and sealed.</p>
            {event.status === "unparsed" && (
              <button onClick={() => navigate("/packs", { state: { sample: event.raw.text } })}>
                Onboard this device in the Pack editor →</button>
            )}
          </>
        )}
      </section>

      {event.status === "accepted" && <ProvenanceTable event={event} active={active} onHover={setActive} />}

      <section className="card">
        <h2>Evidence attached</h2>
        <dl className="evidence">
          <dt>Parser</dt><dd><code>{event.parser.pack_id}@{event.parser.version}</code></dd>
          <dt>Parser digest</dt><dd><code>{event.parser.digest.slice(0, 23)}{event.parser.digest.length > 23 ? "…" : ""}</code></dd>
          <dt>Source hash</dt><dd><code>{event.raw.sha256.slice(0, 23)}…</code></dd>
          <dt>Archive ref</dt><dd><code>{event.raw.archive_ref}</code></dd>
          <dt>Received</dt><dd>{event.received_at}</dd>
          <dt>Round-trip</dt><dd><Pill tone={statusTone(event.roundtrip.status)}>{event.roundtrip.status}</Pill> {event.roundtrip.total_bytes} bytes</dd>
          <dt>Merkle</dt><dd><Pill tone={statusTone(event.merkle.status)}>{event.merkle.status}</Pill> leaf {event.merkle.leaf_index} of {event.merkle.tree_size}
            {event.merkle.inclusion_proof.length > 0 && <span className="muted"> · {event.merkle.inclusion_proof.length}-hash inclusion proof</span>}</dd>
        </dl>
        <Link className="button" to={`/verify/${event.event_id}`}>Verify this event →</Link>
      </section>

      {event.ues && (
        <section className="card">
          <h2>Normalized event (UES / OCSF)</h2>
          <pre className="json">{JSON.stringify(event.ues, null, 2)}</pre>
        </section>
      )}
    </div>
  );
}

function ProvenanceTable({ event, active, onHover }: {
  event: ProofCarryingEvent; active: string | null; onHover: (k: string | null) => void;
}) {
  return (
    <section className="card">
      <h2>Field provenance <span className="muted">· {event.provenance.length} fields, every one traced to its bytes</span></h2>
      <table>
        <thead><tr><th>UES field</th><th>Value</th><th>Source bytes</th><th>Declared transforms</th></tr></thead>
        <tbody>
          {event.provenance.map((p) => (
            <tr key={p.field} className={p.field === active ? "row-active" : ""}
                onMouseEnter={() => onHover(p.bytes ? p.field : null)} onMouseLeave={() => onHover(null)}>
              <td><code>{p.field}</code></td>
              <td><code>{String(p.value)}</code></td>
              <td>{p.bytes ? <code>bytes[{p.bytes[0]}:{p.bytes[1]}]</code>
                           : <span className="muted">derived from {p.derived_from?.join(", ")}</span>}</td>
              <td className="small">{p.transforms.join(" → ")}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}

