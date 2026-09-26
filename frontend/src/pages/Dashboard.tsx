import { Link } from "react-router";
import { getDashboard, listEvents } from "../api";
import { Timeline } from "../components/Timeline";
import { ErrorNote, Loading, num, pct, Pill, Stat, statusTone, summary } from "../components/ui";
import { useAsync } from "../lib/useAsync";

const REFRESH_MS = 2000;

export function Dashboard() {
  const { data: s, error } = useAsync(getDashboard, [], REFRESH_MS);
  const { data: events } = useAsync(() => listEvents({ limit: 10 }), [], REFRESH_MS);
  if (!s) return <><h1>Dashboard</h1>{error ? <ErrorNote error={error} /> : <Loading />}</>;
  const t = s.totals;
  const head = s.tree_head;

  return (
    <>
      <div className="row-between">
        <h1>Dashboard</h1>
        <span className="muted small">{error ? <span className="text-bad">connection lost - retrying</span> : `live · refreshes every ${REFRESH_MS / 1000} s`}</span>
      </div>
      <p className="muted">Perimeter sources normalized into one OCSF-aligned schema, every event archived and sealed · {s.window}</p>

      <div className="stats">
        <Stat label="events received" value={num(t.received)} />
        <Stat label="events / sec" value={t.eps.toFixed(0)} />
        <Stat label="parse success" value={pct(t.parse_success_rate)} tone="ok" />
        <Stat label="round-trip pass" value={pct(t.roundtrip_pass_rate)} tone="ok" />
        <Stat label="blocked (data loss)" value={num(t.blocked)} tone={t.blocked ? "bad" : undefined} />
        <Stat label="dead-letter (unknown)" value={num(t.dead_letter)} tone={t.dead_letter ? "warn" : undefined} />
      </div>

      <div className="grid-2">
        <section className="card">
          <h2>Events per second</h2>
          <Timeline points={s.timeline} />
        </section>
        <section className="card">
          <h2>Evidence log</h2>
          {head ? (
            <dl className="evidence compact">
              <dt>Signed tree head</dt><dd>{num(head.tree_size)} events sealed</dd>
              <dt>Merkle root</dt><dd><code>{head.root.slice(0, 20)}…</code></dd>
              <dt>Signed at</dt><dd>{head.signed_at}</dd>
              <dt>Signature</dt><dd><code>{head.signature}</code></dd>
              <dt>RFC 3161 time</dt><dd>{head.rfc3161_time ?? <span className="muted">unavailable</span>}</dd>
              <dt>Unsealed</dt><dd>{num(Math.max(t.archived - head.tree_size, 0))} events waiting for the next head</dd>
            </dl>
          ) : <p className="muted">No signed tree head yet.</p>}
          <p className="small muted">RFC 6962 Merkle log · Ed25519 tree-head signatures · local RFC 3161 time-stamp authority</p>
        </section>
      </div>

      <section className="card">
        <h2>Sources</h2>
        <table>
          <thead>
            <tr><th>Source</th><th>Format</th><th>Parser pack</th><th className="num">Events</th><th className="num">Parsed</th></tr>
          </thead>
          <tbody>
            {s.sources.length === 0 && <tr><td colSpan={5} className="muted">No events yet - start the replayer.</td></tr>}
            {s.sources.map((src) => (
              <tr key={src.name}>
                <td>{src.family} <span className="muted">({src.name})</span></td>
                <td><code>{src.format}</code></td>
                <td>{src.pack ? <code>{src.pack}</code> : <Link to="/packs">create pack →</Link>}</td>
                <td className="num">{num(src.events)}</td>
                <td className="num"><Pill tone={src.parse_rate === 1 ? "ok" : src.parse_rate > 0.99 ? "warn" : "bad"}>{pct(src.parse_rate)}</Pill></td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card">
        <h2>Schema drift radar</h2>
        {s.drift.length === 0 ? <p className="muted">No drift: every source matches a pack and every byte is explained.</p> :
          s.drift.map((d) => (
            <p key={d.source + d.signal} className="drift">
              <Pill tone={d.signal === "blocked by gate" ? "bad" : "warn"}>{d.signal === "blocked by gate" ? "⚠ " : "? "}{d.signal}</Pill>{" "}
              {d.detail}{" "}
              {d.signal === "unrecognised format" && <Link to="/packs">onboard →</Link>}
              {d.signal === "blocked by gate" && <Link to="/events?status=blocked">inspect →</Link>}
            </p>
          ))}
      </section>

      <section className="card">
        <h2>Latest events</h2>
        {!events ? <Loading /> : (
          <table>
            <thead><tr><th>Event</th><th>Source</th><th>Status</th><th>Summary</th></tr></thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.event_id}>
                  <td><Link to={`/events/${e.event_id}`}><code>{e.event_id}</code></Link></td>
                  <td>{e.source.family}</td>
                  <td><Pill tone={statusTone(e.status)}>{e.status}</Pill></td>
                  <td className="muted">{summary(e)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}
