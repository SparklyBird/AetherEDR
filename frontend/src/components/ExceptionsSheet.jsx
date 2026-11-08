import { useMemo, useState } from "react";
import { api, explain } from "../lib/api";
import { midEllipsis, plural, timeAgo } from "../lib/format";
import { usePolled } from "../lib/hooks";
import { arr } from "../lib/safe";
import { toast } from "../lib/toast";
import { Button, ConfirmDialog, Dialog, Empty, ErrorNote, ErrorPanel, Input, Select, Spinner, Switch, Tag } from "./ui";

function scopeText(e) {
  const what = e.rule_id ? (e.rule_id.endsWith("*") ? `Rules ${e.rule_id}` : `Rule ${e.rule_id}`) : "Every rule";
  const where = e.exe ? "for this program" : e.name ? `for any process named ${e.name}` : "for every program";
  return { what, where };
}

function AddDialog({ open, onClose, onDone, rules }) {
  const [rule, setRule] = useState("");
  const [exe, setExe] = useState("");
  const [name, setName] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  async function save() {
    setBusy(true);
    setError(null);
    try {
      await api("exceptions/", { method: "POST", body: { rule_id: rule, exe: exe.trim(), name: name.trim(), note: note.trim() } });
      toast({ title: "Exception added", body: "Matching alerts were closed.", tone: "good", ms: 4000 });
      setRule(""); setExe(""); setName(""); setNote("");
      onDone();
      onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onClose={onClose} title="Add an exception">
      <div className="space-y-3 p-4">
        <p className="text-[0.8125rem] text-pencil">Every field you fill narrows the match. Leave a field empty to match anything.</p>
        <label className="block">
          <span className="mb-1 block text-[0.8125rem] font-bold">Rule</span>
          <Select value={rule} onChange={(e) => setRule(e.target.value)} className="w-full">
            <option value="">Any rule (needs a program or name below)</option>
            {rules.map((r) => <option key={r.id} value={r.id}>{r.id} {r.title}</option>)}
          </Select>
        </label>
        <label className="block">
          <span className="mb-1 block text-[0.8125rem] font-bold">Program path</span>
          <Input value={exe} onChange={(e) => setExe(e.target.value)} placeholder="c:\program files\vendor\app.exe" className="w-full font-mono !text-xs" />
        </label>
        <label className="block">
          <span className="mb-1 block text-[0.8125rem] font-bold">Process name</span>
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="app.exe" className="w-full font-mono !text-xs" />
        </label>
        <label className="block">
          <span className="mb-1 block text-[0.8125rem] font-bold">Why is this safe?</span>
          <Input value={note} onChange={(e) => setNote(e.target.value)} maxLength={200} className="w-full" />
        </label>
        <ErrorNote error={error} />
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" onClick={save} disabled={busy || !(rule || exe.trim() || name.trim())}>{busy && <Spinner />} Add exception</Button>
        </div>
      </div>
    </Dialog>
  );
}

export default function ExceptionsSheet({ rev, onChanged }) {
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState(null);
  const [busy, setBusy] = useState(false);
  const [text, setText] = useState("");
  const exc = usePolled((signal) => api("exceptions/", { signal }), [rev]);
  const rules = usePolled((signal) => api("rules/", { signal }), []);
  const list = useMemo(() => {
    const q = text.trim().toLowerCase();
    return arr(exc.data?.results ?? exc.data)
      .slice()
      .sort((a, b) => (a.created_at < b.created_at ? 1 : -1))
      .filter((e) => !q || `${e.rule_id} ${e.exe} ${e.name} ${e.note}`.toLowerCase().includes(q));
  }, [exc.data, text]);
  const total = arr(exc.data?.results ?? exc.data).length;

  const refresh = () => (onChanged?.(), exc.reload());

  async function toggle(e, enabled) {
    try {
      await api(`exceptions/${e.id}/`, { method: "PATCH", body: { enabled } });
      toast({ title: enabled ? "Exception on" : "Exception off", body: enabled ? "Matching findings are muted again." : "Its findings count again and alerts reopen.", tone: "good", ms: 3500 });
      refresh();
    } catch (err) {
      explain(err, "Could not change the exception");
    }
  }
  async function remove() {
    setBusy(true);
    try {
      await api(`exceptions/${removing.id}/`, { method: "DELETE" });
      toast({ title: "Exception removed", body: "Findings it hid will raise alerts again.", tone: "good", ms: 4000 });
      setRemoving(null);
      refresh();
    } catch (err) {
      explain(err, "Could not remove the exception");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex h-full min-h-0 flex-col bg-sheet">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-rule2 bg-plate px-4 py-2">
        <Input type="search" value={text} onChange={(e) => setText(e.target.value)} placeholder="Rule, path, name or note" aria-label="Search exceptions" className="w-72 max-w-full" />
        <span className="text-xs text-pencil">{exc.data && plural(total, "exception")}</span>
        <Button variant="primary" size="sm" className="ml-auto" onClick={() => setAdding(true)}>Add exception</Button>
      </div>
      <p className="border-b border-rule px-4 py-2 text-xs text-pencil">
        An exception stops a finding from counting toward the risk score. Nothing is deleted: turn one off or remove it and the alerts come back.
      </p>
      <ErrorPanel error={exc.error && !exc.data ? exc.error : null} onRetry={exc.reload} title="Could not load exceptions" />
      <div className="min-h-0 flex-1 overflow-auto">
        {!exc.data && !exc.error ? (
          <div className="grid place-items-center p-10"><Spinner /></div>
        ) : !list.length && exc.data ? (
          <Empty title={total ? "No exception matches" : "No exceptions yet"} action={!total && <Button size="sm" onClick={() => setAdding(true)}>Add exception</Button>}>
            {total ? "Try a shorter search." : "Use Trust on an alert or a process when you know why it behaves this way."}
          </Empty>
        ) : (
          <ul>
            {list.map((e) => {
              const { what, where } = scopeText(e);
              return (
                <li key={e.id} className={`flex flex-wrap items-start gap-x-4 gap-y-2 border-b border-rule px-4 py-3 ${e.enabled ? "" : "opacity-55"}`}>
                  <div className="min-w-0 flex-1">
                    <p>
                      <span className="font-bold">{what}</span> <span className="text-pencil">{where}</span>
                    </p>
                    {(e.exe || e.name) && <p className="break-all font-mono text-xs text-graphite" title={e.exe || e.name}>{e.exe ? midEllipsis(e.exe, 90) : e.name}</p>}
                    {e.note && <p className="mt-0.5 text-[0.8125rem] italic text-pencil">“{e.note}”</p>}
                    <p className="mt-1 flex flex-wrap items-center gap-2 text-xs text-graphite">
                      added {timeAgo(e.created_at)}
                      <Tag>{plural(e.silenced || 0, "alert")} silenced</Tag>
                    </p>
                  </div>
                  <div className="flex items-center gap-3">
                    <Switch checked={!!e.enabled} onChange={(v) => toggle(e, v)} label={e.enabled ? "On" : "Off"} />
                    <Button size="sm" variant="danger" onClick={() => setRemoving(e)}>Remove</Button>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>
      <AddDialog open={adding} onClose={() => setAdding(false)} onDone={refresh} rules={arr(rules.data?.rules)} />
      <ConfirmDialog open={!!removing} title="Remove this exception?" confirm="Remove" danger busy={busy} onConfirm={remove} onClose={() => setRemoving(null)}>
        {removing && <p>{scopeText(removing).what} {scopeText(removing).where}. Findings it hid will raise alerts again.</p>}
      </ConfirmDialog>
    </div>
  );
}
