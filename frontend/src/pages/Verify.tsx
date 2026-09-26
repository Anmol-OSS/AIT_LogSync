import { useState } from "react";
import { useNavigate, useParams } from "react-router";
import { listEvents, restoreEvent, tamperEvent, verifyEvent } from "../api";
import { RawLine } from "../components/RawLine";
import { CheckList, ErrorNote, Loading, Pill, statusTone } from "../components/ui";
import { useAsync } from "../lib/useAsync";
import type { VerifyReport } from "../types";

export function Verify() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { data: events, error } = useAsync(() => listEvents({ limit: 30, status: "accepted" }), []);
  const [report, setReport] = useState<VerifyReport>();
  const [busy, setBusy] = useState<string>();
  const [failure, setFailure] = useState<string>();

  if (error) return <><h1>Verify event</h1><ErrorNote error={error} /></>;
  if (!events) return <Loading />;
  const selectedId = id ?? events[0]?.event_id;
  const event = events.find((e) => e.event_id === selectedId);

  async function run(label: string, action: () => Promise<unknown>) {
    if (!selectedId) return;
    setBusy(label);
    setFailure(undefined);
    try {
      await action();
      setReport(await verifyEvent(selectedId));
    } catch (e) {
      setFailure(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(undefined);
    }
  }

  return (
    <>
      <h1>Verify event</h1>
      <p className="muted">Verification trusts nothing stored about the event: it starts from the archived bytes,
        re-parses them with the signed pack, and re-checks the Merkle proof against the signed tree head.</p>

      <section className="card">
        {events.length === 0 ? <p className="muted">No accepted events yet - start the replayer.</p> : (
          <label className="field">
            <span>Event</span>
            <select value={selectedId} onChange={(e) => { setReport(undefined); navigate(`/verify/${e.target.value}`); }}>
              {!event && selectedId && <option value={selectedId}>{selectedId}</option>}
              {events.map((e) => <option key={e.event_id} value={e.event_id}>{e.event_id} · {e.source.family}</option>)}
            </select>
          </label>
        )}
        <div className="actions">
          <button onClick={() => run("Verifying", async () => undefined)} disabled={!!busy || !selectedId}>Verify event</button>
          <button className="danger" onClick={() => run("Tampering", () => tamperEvent(selectedId!))} disabled={!!busy || !selectedId}>
            Alter one archived byte, then verify</button>
          {report?.tampered && (
            <button className="secondary" onClick={() => run("Restoring", () => restoreEvent(selectedId!))} disabled={!!busy}>
              Restore the original byte</button>
          )}
        </div>
        {failure && <p className="error-note">{failure}</p>}
        {report?.tampered && report.tampered_raw !== undefined && report.tampered_byte !== undefined ? (
          <>
            <p className="small muted">Archived bytes as they are now (changed byte {report.tampered_byte} highlighted):</p>
            <RawLine text={report.tampered_raw} tone="danger"
                     highlights={[{ key: "tampered", range: [report.tampered_byte, report.tampered_byte + 1] }]} />
          </>
        ) : event && <RawLine text={event.raw.text} highlights={[]} />}
      </section>

      {busy && <Loading what={busy} />}
      {report && !busy && (
        <section className="card">
          <div className="row-between">
            <h2>Verification report <span className="muted">· {report.event_id}</span></h2>
            <Pill tone={statusTone(report.overall)}>{report.overall.toUpperCase()}</Pill>
          </div>
          <CheckList checks={report.checks} />
        </section>
      )}
    </>
  );
}
