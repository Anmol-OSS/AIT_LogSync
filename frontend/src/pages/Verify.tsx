import { useState } from "react";
import { useNavigate, useParams } from "react-router";
import { listEvents, verifyEvent } from "../api";
import { RawLine } from "../components/RawLine";
import { CheckList, Loading, Pill, statusTone } from "../components/ui";
import { useAsync } from "../lib/useAsync";
import type { VerifyReport } from "../types";

export function Verify() {
  const { id } = useParams();
  const navigate = useNavigate();
  const events = useAsync(listEvents, []);
  const [report, setReport] = useState<VerifyReport>();
  const [running, setRunning] = useState(false);

  if (!events) return <Loading />;
  const verifiable = events.filter((e) => e.status === "accepted");
  const selectedId = id ?? verifiable[0]?.event_id;
  const event = verifiable.find((e) => e.event_id === selectedId);

  async function run(tamper: boolean) {
    if (!selectedId) return;
    setRunning(true);
    setReport(await verifyEvent(selectedId, tamper));
    setRunning(false);
  }

  return (
    <>
      <h1>Verify event</h1>
      <p className="muted">Verification starts from the archived bytes and re-checks the whole proof chain.</p>

      <section className="card">
        <label className="field">
          <span>Event</span>
          <select value={selectedId} onChange={(e) => { setReport(undefined); navigate(`/verify/${e.target.value}`); }}>
            {verifiable.map((e) => <option key={e.event_id} value={e.event_id}>{e.event_id} · {e.source.family}</option>)}
          </select>
        </label>
        <div className="actions">
          <button onClick={() => run(false)} disabled={running}>Verify event</button>
          <button className="danger" onClick={() => run(true)} disabled={running}>Alter one archived byte, then verify</button>
        </div>
        {event && !report?.tampered && <RawLine text={event.raw.text} highlights={[]} />}
        {report?.tampered && report.tampered_raw !== undefined && report.tampered_byte !== undefined && (
          <>
            <p className="small muted">Archived bytes after tampering (changed byte {report.tampered_byte} highlighted):</p>
            <RawLine text={report.tampered_raw} tone="danger"
                     highlights={[{ key: "tampered", range: [report.tampered_byte, report.tampered_byte + 1] }]} />
          </>
        )}
      </section>

      {running && <Loading />}
      {report && !running && (
        <section className="card">
          <div className="row-between">
            <h2>Verification report</h2>
            <Pill tone={statusTone(report.overall)}>{report.overall.toUpperCase()}</Pill>
          </div>
          <CheckList checks={report.checks} />
        </section>
      )}
    </>
  );
}
