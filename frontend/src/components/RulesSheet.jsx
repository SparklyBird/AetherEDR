import { useMemo, useState } from "react";
import { api, explain } from "../lib/api";
import { plural } from "../lib/format";
import { useDebounced, usePolled } from "../lib/hooks";
import { arr } from "../lib/safe";
import { toast } from "../lib/toast";
import { Button, Empty, ErrorPanel, Input, Segmented, Spinner, Tag } from "./ui";

const weightColor = (w) => (w >= 80 ? "var(--redline)" : w >= 60 ? "var(--marker)" : w >= 40 ? "var(--highlight)" : "var(--chalk)");

export default function RulesSheet({ rev, onChanged }) {
  const [text, setText] = useState("");
  const [cat, setCat] = useState("all");
  const [open, setOpen] = useState(null);
  const [busy, setBusy] = useState(null);
  const q = useDebounced(text, 150).trim().toLowerCase();
  const rules = usePolled((signal) => api("rules/", { signal }), [rev]);
  const exc = usePolled((signal) => api("exceptions/", { signal }), [rev]);

  const list = arr(rules.data?.rules);
  const globals = useMemo(() => {
    const m = new Map();
    for (const e of arr(exc.data?.results ?? exc.data)) if (e.enabled && !e.exe && !e.name && e.rule_id) m.set(e.rule_id, e.id);
    return m;
  }, [exc.data]);
  const cats = useMemo(() => [...new Set(list.map((r) => r.category))].sort(), [list]);
  const shown = useMemo(
    () => list.filter((r) => (cat === "all" || r.category === cat) && (!q || `${r.id} ${r.title} ${r.tactic} ${r.technique} ${r.summary}`.toLowerCase().includes(q))),
    [list, cat, q],
  );

  async function mute(r) {
    setBusy(r.id);
    try {
      await api("exceptions/", { method: "POST", body: { rule_id: r.id, note: "Muted from the Rules sheet" } });
      toast({ title: `${r.id} muted everywhere`, body: "Its open alerts were closed. Unmute it here at any time.", tone: "good", ms: 5000 });
      onChanged?.();
      rules.reload();
      exc.reload();
    } catch (e) {
      explain(e, "Could not mute this rule");
    } finally {
      setBusy(null);
    }
  }
  async function unmute(r) {
    const id = globals.get(r.id);
    if (id == null) return toast({ title: "Muted by a narrower exception", body: "Open the Exceptions sheet to change it.", ms: 4500 });
    setBusy(r.id);
    try {
      await api(`exceptions/${id}/`, { method: "DELETE" });
      toast({ title: `${r.id} is active again`, tone: "good", ms: 3500 });
      onChanged?.();
      rules.reload();
      exc.reload();
    } catch (e) {
      explain(e, "Could not unmute this rule");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="flex h-full min-h-0 flex-col bg-sheet">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-rule2 bg-plate px-4 py-2">
        <Input type="search" value={text} onChange={(e) => setText(e.target.value)} placeholder="Rule, technique or tactic" aria-label="Search rules" className="w-72 max-w-full" />
        <Segmented size="sm" label="Category" value={cat} onChange={setCat} options={[{ value: "all", label: "All" }, ...cats.map((c) => ({ value: c, label: c }))]} />
        <span className="ml-auto text-xs text-pencil">
          {rules.loading && <Spinner />}
          {rules.data && `${plural(shown.length, "rule")} of ${list.length}`}
        </span>
      </div>
      {rules.data && (
        <p className="border-b border-rule px-4 py-2 text-xs text-pencil">
          A process raises alerts at risk {rules.data.alert_threshold} or more, and a single finding must weigh {rules.data.min_alert_weight} or more. Weights combine so that two strong findings score higher than one, never above 100.
        </p>
      )}
      <ErrorPanel error={rules.error && !rules.data ? rules.error : null} onRetry={rules.reload} title="Could not load the rules" />
      <div className="min-h-0 flex-1 overflow-auto">
        {!rules.data && !rules.error ? (
          <div className="grid place-items-center p-10"><Spinner /></div>
        ) : !shown.length && rules.data ? (
          <Empty title="No rule matches" action={<Button size="sm" onClick={() => (setText(""), setCat("all"))}>Clear filters</Button>} />
        ) : (
          <table className="w-full min-w-[760px] text-left text-[0.8125rem]">
            <thead className="sticky top-0 z-10 bg-plate text-xs text-pencil shadow-[0_1px_0_var(--rule2)]">
              <tr>
                <th className="py-2 pl-4 pr-2 font-medium">Rule</th>
                <th className="px-2 py-2 font-medium">Weight</th>
                <th className="px-2 py-2 font-medium">Technique</th>
                <th className="px-2 py-2 font-medium">Alerts</th>
                <th className="px-2 py-2 font-medium"><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {shown.map((r) => {
                const on = open === r.id;
                return (
                  <tr key={r.id} className={`border-b border-rule align-top ${r.muted ? "opacity-60" : ""}`}>
                    <td className="py-2 pl-4 pr-2">
                      <button type="button" className="text-left" aria-expanded={on} onClick={() => setOpen(on ? null : r.id)}>
                        <span className="mr-2 font-mono text-xs text-graphite">{r.id}</span>
                        <span className="font-bold">{r.title}</span>
                      </button>
                      <div className="text-xs text-graphite">{r.category}</div>
                      {on && <p className="mt-1.5 max-w-xl text-pencil">{r.summary || "No description."}</p>}
                    </td>
                    <td className="px-2 py-2">
                      <span className="inline-flex items-center gap-2" title={`Contributes up to ${r.weight} to the risk score`}>
                        <span className="relative h-1.5 w-16 bg-rule" aria-hidden><span className="absolute inset-y-0 left-0" style={{ width: `${Math.min(100, r.weight)}%`, background: weightColor(r.weight) }} /></span>
                        <span className="tabular">{r.weight}</span>
                      </span>
                    </td>
                    <td className="px-2 py-2 text-xs text-pencil">{r.tactic}{r.technique && <> <Tag mono>{r.technique}</Tag></>}</td>
                    <td className="px-2 py-2 tabular text-pencil">{r.alerts_open > 0 ? <span className="text-ink">{r.alerts_open} open</span> : "0 open"}<span className="text-graphite"> / {r.alerts_total}</span></td>
                    <td className="whitespace-nowrap px-2 py-2 text-right">
                      {r.muted ? (
                        <>
                          <Tag tone="var(--marker)">muted</Tag>{" "}
                          <Button size="sm" onClick={() => unmute(r)} disabled={busy === r.id}>Unmute</Button>
                        </>
                      ) : (
                        <Button size="sm" variant="ghost" onClick={() => mute(r)} disabled={busy === r.id} title="Stop raising this alert for every program">Mute everywhere</Button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
