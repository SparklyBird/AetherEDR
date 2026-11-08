import { useEffect, useState } from "react";
import { api, explain } from "../lib/api";
import { midEllipsis, plural } from "../lib/format";
import { toast } from "../lib/toast";
import { Button, Dialog, ErrorNote, Input, Spinner } from "./ui";

/**
 * Turns a false positive into an exception. `target` = { rules: [{id,title}], exe, name }.
 * Exceptions only silence findings, nothing is deleted, and they can be removed later.
 */
export default function TrustDialog({ target, onClose, onDone }) {
  const [scope, setScope] = useState("rule-program");
  const [picked, setPicked] = useState(new Set());
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (!target) return;
    setScope(target.exe ? "rule-program" : "rule-name");
    setPicked(new Set(target.rules.map((r) => r.id)));
    setNote("");
    setError(null);
  }, [target]);

  if (!target) return <Dialog open={false} onClose={onClose} />;
  const { rules, exe, name } = target;
  const options = [
    { id: "rule-program", ok: !!exe, title: "These detections, for this program", body: exe ? midEllipsis(exe, 52) : "Needs a known file path", needsRules: true },
    { id: "rule-name", ok: !!name, title: `These detections, for any process named ${name || "?"}`, body: "Matches by name, wherever the file lives", needsRules: true },
    { id: "program", ok: !!exe, title: "Everything from this program", body: "Broad: also hides future findings, even real attacks, from this exact path", needsRules: false, warn: true },
    { id: "rule-all", ok: true, title: "These detections, everywhere", body: "Broad: turns the rule off for every program", needsRules: true, warn: true },
  ];
  const cur = options.find((o) => o.id === scope) || options[0];
  const chosen = rules.filter((r) => picked.has(r.id));
  const canSave = cur.ok && (!cur.needsRules || chosen.length > 0);

  async function save() {
    setBusy(true);
    setError(null);
    const base = { note: note.trim() };
    const bodies = cur.needsRules
      ? chosen.map((r) => ({ ...base, rule_id: r.id, ...(scope === "rule-program" ? { exe } : scope === "rule-name" ? { name } : {}) }))
      : [{ ...base, exe }];
    try {
      for (const b of bodies) await api("exceptions/", { method: "POST", body: b });
      toast({ title: bodies.length > 1 ? `${bodies.length} exceptions added` : "Exception added", body: "Matching alerts were closed. Remove the exception on the Exceptions sheet to bring them back.", tone: "good", ms: 6000 });
      onDone?.();
      onClose();
    } catch (e) {
      setError(e);
      explain(e, "Could not add the exception");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open onClose={onClose} title="Trust this behaviour" wide>
      <div className="space-y-4 p-4">
        <p className="text-[0.8125rem] text-pencil">
          Use this when you know why the program does it. Matching findings stop counting toward the risk score and stop raising alerts.
        </p>

        <fieldset className="space-y-1.5">
          <legend className="mb-1 text-[0.8125rem] font-bold">Apply to</legend>
          {options.map((o) => (
            <label key={o.id} className={`flex cursor-pointer items-start gap-3 border px-3 py-2 ${scope === o.id ? "border-ink bg-plate2" : "border-rule hover:border-rule2"} ${o.ok ? "" : "pointer-events-none opacity-40"}`}>
              <input type="radio" name="trust-scope" checked={scope === o.id} onChange={() => setScope(o.id)} className="mt-1 accent-[var(--ink)]" disabled={!o.ok} />
              <span className="min-w-0">
                <span className="block text-[0.8125rem] font-medium">{o.title}</span>
                <span className={`block break-all text-xs ${o.warn ? "text-marker" : "text-graphite"}`}>{o.body}</span>
              </span>
            </label>
          ))}
        </fieldset>

        {cur.needsRules && (
          <fieldset className="space-y-1">
            <legend className="mb-1 text-[0.8125rem] font-bold">Detections ({plural(chosen.length, "selected", "selected")})</legend>
            {rules.map((r) => (
              <label key={r.id} className="flex cursor-pointer items-start gap-2.5 text-[0.8125rem]">
                <input
                  type="checkbox"
                  className="mt-1 accent-[var(--ink)]"
                  checked={picked.has(r.id)}
                  onChange={(e) => setPicked((s) => { const n = new Set(s); e.target.checked ? n.add(r.id) : n.delete(r.id); return n; })}
                />
                <span>
                  <span className="mr-1.5 font-mono text-xs text-graphite">{r.id}</span>
                  {r.title}
                </span>
              </label>
            ))}
          </fieldset>
        )}

        <label className="block">
          <span className="mb-1 block text-[0.8125rem] font-bold">Why is this safe? (optional)</span>
          <Input value={note} onChange={(e) => setNote(e.target.value)} maxLength={200} placeholder="For example: Steam's browser engine compiles JavaScript" className="w-full" />
        </label>

        <ErrorNote error={error} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={save} disabled={busy || !canSave}>
            {busy && <Spinner />} Add exception
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
