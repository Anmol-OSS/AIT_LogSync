import { useEffect, useState } from "react";
import { Link, useLocation } from "react-router";
import { approvePack, type ApproveResult, draftPack, listEvents, listPacks } from "../api";
import { RawLine } from "../components/RawLine";
import { CheckList, ErrorNote, Pill, pct } from "../components/ui";
import { useAsync } from "../lib/useAsync";
import type { DraftField, PackDraft } from "../types";

const STEPS = ["Drop a sample", "See the draft", "Fix and approve", "Sign and ship"];

export function PackEditor() {
  const location = useLocation();
  const [step, setStep] = useState(0);
  const [sample, setSample] = useState("");
  const [draft, setDraft] = useState<PackDraft>();
  const [fields, setFields] = useState<DraftField[]>([]);
  const [approved, setApproved] = useState<ApproveResult>();
  const [busy, setBusy] = useState<string>();
  const [failure, setFailure] = useState<string>();
  const packs = useAsync(listPacks, [approved]);

  // Pre-fill with the newest dead-lettered lines: the unknown device's real traffic.
  useEffect(() => {
    const fromEvent = (location.state as { sample?: string } | null)?.sample;
    if (fromEvent) { setSample(fromEvent); return; }
    listEvents({ status: "unparsed", limit: 5 }).then(
      (evs) => setSample((s) => s || evs.map((e) => e.raw.text).join("\n")),
      () => undefined,
    );
  }, [location.state]);

  async function makeDraft() {
    setBusy("Drafting: Drain finds the structure, the offline LLM labels it, the gate validates it (about a minute on CPU)");
    setFailure(undefined);
    try {
      const d = await draftPack(sample.split("\n").filter((l) => l.trim()));
      setDraft(d);
      setFields(d.fields);
      setStep(1);
    } catch (e) {
      setFailure(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(undefined);
    }
  }

  async function approve() {
    if (!draft) return;
    setBusy("Re-validating, signing and hot-loading the pack");
    setFailure(undefined);
    try {
      setApproved(await approvePack(draft.draft_id, fields.map((f) => ({ name: f.name, mapped_to: f.mapped_to }))));
      setStep(3);
    } catch (e) {
      setFailure(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(undefined);
    }
  }

  function remap(name: string, target: string) {
    setFields((fs) => fs.map((f) => (f.name === name ? { ...f, mapped_to: target } : f)));
  }

  function reset() {
    setStep(0); setDraft(undefined); setApproved(undefined); setSample(""); setFailure(undefined);
  }

  const gateOk = draft?.validation.every((c) => c.status === "pass");

  return (
    <>
      <h1>Parser Pack Editor</h1>
      <p className="muted">An analyst onboards a new device: no code, no hand-written YAML.
        LLM proposes. Deterministic tests decide. Human approves.</p>

      <ol className="stepper">
        {STEPS.map((s, i) => (
          <li key={s} className={i === step ? "current" : i < step ? "done" : ""}><span>{i + 1}</span>{s}</li>
        ))}
      </ol>

      {failure && <p className="error-note">{failure}</p>}

      {step === 0 && (
        <section className="card">
          <h2>1 · Paste sample lines from the unknown device</h2>
          <p className="small muted">Pre-filled with the newest dead-lettered lines. Log lines reach the model only as
            JSON data inside a fixed prompt - never as instructions.</p>
          <textarea rows={7} value={sample} onChange={(e) => setSample(e.target.value)} spellCheck={false}
                    placeholder="No dead-lettered lines yet. Start the replayer, or paste lines here." />
          <div className="actions">
            <button onClick={makeDraft} disabled={!!busy || !sample.trim()}>{busy ? "Drafting…" : "Draft a parser"}</button>
          </div>
          {busy && <p className="muted small">{busy}…</p>}
        </section>
      )}

      {step >= 1 && step < 3 && draft && (
        <>
          <section className="card">
            <div className="row-between">
              <h2>2 · Auto-drafted pattern</h2>
              <span><Pill tone={draft.confidence >= 0.95 ? "ok" : "bad"}>confidence {draft.confidence.toFixed(2)}</Pill>{" "}
                <span className="muted small">by {draft.generator}</span></span>
            </div>
            <p className="small muted">Detected <code>{draft.detected.fingerprint}</code> · {draft.detected.lines} dead-lettered
              lines from {draft.detected.source_ip} · confidence = share of held-out lines the pattern fully explains.</p>
            <pre className="json">{draft.pattern}</pre>
            <RawLine text={draft.sample[0]} highlights={fields.map((f) => ({ key: f.name, range: f.bytes }))} />
            <h3>Validation gate</h3>
            <CheckList checks={draft.validation} />
            {!gateOk && <p className="text-bad small">The gate failed - this draft cannot be approved. Paste more varied lines and draft again.</p>}
            {step === 1 && gateOk && <div className="actions"><button onClick={() => setStep(2)}>Review field mapping →</button></div>}
            {step === 1 && !gateOk && <div className="actions"><button className="secondary" onClick={reset}>← Start over</button></div>}
          </section>

          {step === 2 && (
            <section className="card">
              <h2>3 · Map fields to the UES</h2>
              <p className="small muted">Suggestions come from the model and are type-checked. Correct anything that is wrong;
                fields left on "(ignore)" are still kept, under <code>unmapped.*</code> - nothing is dropped.</p>
              <table>
                <thead><tr><th>Captured</th><th>Sample value</th><th>Source bytes</th><th>Maps to UES field</th></tr></thead>
                <tbody>
                  {fields.map((f) => (
                    <tr key={f.name}>
                      <td><code>{f.name}</code> <span className="muted small">%{`{${f.grok}}`}</span></td>
                      <td><code>{f.sample_value}</code></td>
                      <td><code>bytes[{f.bytes[0]}:{f.bytes[1]}]</code></td>
                      <td>
                        <select value={f.mapped_to} onChange={(e) => remap(f.name, e.target.value)}>
                          {draft.ues_targets.map((t) => <option key={t} value={t}>{t}</option>)}
                        </select>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="actions">
                <button onClick={() => setStep(1)} className="secondary">← Back</button>
                <button onClick={approve} disabled={!!busy}>{busy ? "Signing…" : "Approve & sign"}</button>
              </div>
              {busy && <p className="muted small">{busy}…</p>}
            </section>
          )}
        </>
      )}

      {step === 3 && approved && (
        <section className="card">
          <h2>4 · Signed and shipped</h2>
          <dl className="evidence">
            <dt>Pack</dt><dd><code>{approved.pack_id}@{approved.version}</code></dd>
            <dt>Mapped fields</dt><dd>{approved.mapped_fields}</dd>
            <dt>Signature</dt><dd><code>{approved.signature}</code></dd>
            <dt>Status</dt><dd><Pill tone="ok">{approved.status}</Pill></dd>
          </dl>
          <div className="actions">
            <Link className="button" to="/events?status=accepted">See the re-parsed events →</Link>
            <button className="secondary" onClick={reset}>Onboard another device</button>
          </div>
        </section>
      )}

      <section className="card">
        <h2>Active parser packs</h2>
        <ErrorNote error={packs.error} />
        <table>
          <thead><tr><th>Pack</th><th>Vendor / product</th><th>Format</th><th>Signature</th><th>Digest</th></tr></thead>
          <tbody>
            {packs.data?.map((p) => (
              <tr key={p.pack_id}>
                <td><code>{p.pack_id}@{p.version}</code></td>
                <td>{p.vendor} {p.product}</td>
                <td><code>{p.format}</code></td>
                <td><Pill tone={p.signed ? "ok" : "bad"}>{p.signed ? "Ed25519 valid" : "INVALID"}</Pill></td>
                <td><code className="small">{p.digest.slice(0, 19)}…</code></td>
              </tr>
            ))}
          </tbody>
        </table>
        <p className="small muted">{packs.data ? `${packs.data.length} packs` : ""} {draft ? `· last draft ${pct(draft.confidence)} confidence` : ""}</p>
      </section>
    </>
  );
}
