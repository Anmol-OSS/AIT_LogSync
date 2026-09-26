import { useState } from "react";
import { approvePack, DEMO_UNKNOWN_SAMPLE, draftPack } from "../api";
import { RawLine } from "../components/RawLine";
import { CheckList, Pill } from "../components/ui";
import type { DraftField, PackDraft } from "../types";

const STEPS = ["Drop a sample", "See the draft", "Fix and approve", "Sign and ship"];

type Approved = Awaited<ReturnType<typeof approvePack>>;

export function PackEditor() {
  const [step, setStep] = useState(0);
  const [sample, setSample] = useState(DEMO_UNKNOWN_SAMPLE);
  const [draft, setDraft] = useState<PackDraft>();
  const [fields, setFields] = useState<DraftField[]>([]);
  const [approved, setApproved] = useState<Approved>();
  const [busy, setBusy] = useState(false);

  async function makeDraft() {
    setBusy(true);
    const d = await draftPack(sample.split("\n").filter((l) => l.trim()));
    setDraft(d);
    setFields(d.fields);
    setBusy(false);
    setStep(1);
  }

  async function approve() {
    if (!draft) return;
    setBusy(true);
    setApproved(await approvePack(draft.draft_id, fields));
    setBusy(false);
    setStep(3);
  }

  function remap(name: string, target: string) {
    setFields((fs) => fs.map((f) => (f.name === name ? { ...f, mapped_to: target } : f)));
  }

  return (
    <>
      <h1>Parser Pack Editor</h1>
      <p className="muted">An analyst onboards a new device: no code, no hand-written YAML.
        The offline LLM proposes, deterministic tests decide, a human approves.</p>

      <ol className="stepper">
        {STEPS.map((s, i) => (
          <li key={s} className={i === step ? "current" : i < step ? "done" : ""}><span>{i + 1}</span>{s}</li>
        ))}
      </ol>

      {step === 0 && (
        <section className="card">
          <h2>1 · Paste sample lines from the unknown device</h2>
          <textarea rows={6} value={sample} onChange={(e) => setSample(e.target.value)} spellCheck={false} />
          <p className="small muted">Log lines are passed to the model as data inside a fixed prompt, never as instructions.</p>
          <div className="actions">
            <button onClick={makeDraft} disabled={busy || !sample.trim()}>{busy ? "Drafting…" : "Draft a parser"}</button>
          </div>
        </section>
      )}

      {step >= 1 && draft && step < 3 && (
        <>
          <section className="card">
            <div className="row-between">
              <h2>2 · Auto-drafted pattern</h2>
              <span><Pill tone="ok">confidence {draft.confidence.toFixed(2)}</Pill> <span className="muted small">by {draft.generator}</span></span>
            </div>
            <pre className="json">{draft.pattern}</pre>
            <RawLine text={draft.sample[0]} highlights={fields.map((f) => ({ key: f.name, range: f.bytes }))} />
            <h3>Validation gate</h3>
            <CheckList checks={draft.validation} />
            {step === 1 && <div className="actions"><button onClick={() => setStep(2)}>Review field mapping →</button></div>}
          </section>

          {step === 2 && (
            <section className="card">
              <h2>3 · Map fields to the UES</h2>
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
                <button onClick={approve} disabled={busy}>{busy ? "Signing…" : "Approve & sign"}</button>
              </div>
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
            <button className="secondary" onClick={() => { setStep(0); setDraft(undefined); setApproved(undefined); }}>Onboard another device</button>
          </div>
        </section>
      )}
    </>
  );
}
