import { Link } from "react-router";
import { getDashboard, listEvents } from "../api";
import { Loading, num, pct, Pill, Stat, statusTone } from "../components/ui";
import { useAsync } from "../lib/useAsync";

export function Dashboard() {
  const summary = useAsync(getDashboard, []);
  const events = useAsync(listEvents, []);
  if (!summary) return <Loading />;
  const t = summary.totals;

  return (
    <>
      <h1>Dashboard</h1>
      <p className="muted">Five perimeter source families normalized into one schema · {summary.window}</p>

      <div className="stats">
        <Stat label="events received" value={num(t.received)} />
        <Stat label="events / sec" value={t.eps.toFixed(0)} />
        <Stat label="parse success" value={pct(t.parse_success_rate)} tone="ok" />
        <Stat label="round-trip pass" value={pct(t.roundtrip_pass_rate)} tone="ok" />
        <Stat label="blocked (data loss)" value={num(t.blocked)} tone="bad" />
        <Stat label="dead-letter (unknown)" value={num(t.dead_letter)} tone="warn" />
      </div>

      <section className="card">
        <h2>Sources</h2>
        <table>
          <thead>
            <tr><th>Source</th><th>Format</th><th>Parser pack</th><th className="num">Events</th><th className="num">Parsed</th></tr>
          </thead>
          <tbody>
            {summary.sources.map((s) => (
              <tr key={s.name}>
                <td>{s.family} <span className="muted">({s.name})</span></td>
                <td><code>{s.format}</code></td>
                <td>{s.pack ? <code>{s.pack}</code> : <Link to="/packs">create pack →</Link>}</td>
                <td className="num">{num(s.events)}</td>
                <td className="num"><Pill tone={s.parse_rate === 1 ? "ok" : s.parse_rate > 0.99 ? "warn" : "bad"}>{pct(s.parse_rate)}</Pill></td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <section className="card">
        <h2>Schema drift</h2>
        {summary.drift.map((d) => (
          <p key={d.source}><Pill tone="warn">{d.signal}</Pill> {d.detail}</p>
        ))}
      </section>

      <section className="card">
        <h2>Latest events</h2>
        {!events ? <Loading /> : (
          <table>
            <thead><tr><th>Event</th><th>Source</th><th>Status</th><th>Summary</th></tr></thead>
            <tbody>
              {events.map((e) => {
                const f = Object.fromEntries(e.provenance.map((p) => [p.field, p.value]));
                return (
                  <tr key={e.event_id}>
                    <td><Link to={`/events/${e.event_id}`}><code>{e.event_id}</code></Link></td>
                    <td>{e.source.family}</td>
                    <td><Pill tone={statusTone(e.status)}>{e.status}</Pill></td>
                    <td className="muted">
                      {e.status === "accepted"
                        ? `${f["src_endpoint.ip"]} → ${f["dst_endpoint.ip"]}:${f["dst_endpoint.port"]} · ${f["disposition"]}`
                        : e.roundtrip.reason}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}
