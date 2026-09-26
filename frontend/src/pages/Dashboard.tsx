import { Link } from "react-router";
import { getDashboard, listEvents } from "../api";
import { ErrorNote, Loading, num, pct, Pill, Stat, statusTone, summary } from "../components/ui";
import { useAsync } from "../lib/useAsync";

export function Dashboard() {
  const { data: s, error } = useAsync(getDashboard, []);
  const { data: events } = useAsync(() => listEvents({ limit: 12 }), []);
  if (error) return <><h1>Dashboard</h1><ErrorNote error={error} /></>;
  if (!s) return <Loading />;
  const t = s.totals;

  return (
    <>
      <h1>Dashboard</h1>
      <p className="muted">Perimeter sources normalized into one schema · {s.window}</p>

      <div className="stats">
        <Stat label="events received" value={num(t.received)} />
        <Stat label="events / sec" value={t.eps.toFixed(0)} />
        <Stat label="parse success" value={pct(t.parse_success_rate)} tone="ok" />
        <Stat label="round-trip pass" value={pct(t.roundtrip_pass_rate)} tone="ok" />
        <Stat label="blocked (data loss)" value={num(t.blocked)} tone={t.blocked ? "bad" : undefined} />
        <Stat label="dead-letter (unknown)" value={num(t.dead_letter)} tone={t.dead_letter ? "warn" : undefined} />
      </div>

      <section className="card">
        <h2>Sources</h2>
        <table>
          <thead>
            <tr><th>Source</th><th>Format</th><th>Parser pack</th><th className="num">Events</th><th className="num">Parsed</th></tr>
          </thead>
          <tbody>
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
