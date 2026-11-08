import { useEffect, useMemo, useRef, useState } from "react";
import { api } from "../lib/api";
import { midEllipsis } from "../lib/format";
import { useDebounced } from "../lib/hooks";
import { arr } from "../lib/safe";
import { Dialog, Kbd, RiskGauge, Spinner } from "./ui";

/** Ctrl K: all commands plus live process search. */
export default function CommandPalette({ open, onClose, commands, host, onPickProcess }) {
  const [text, setText] = useState("");
  const [idx, setIdx] = useState(0);
  const [procs, setProcs] = useState({ q: "", rows: [], busy: false, error: null });
  const q = useDebounced(text, 200).trim();
  const list = useRef(null);

  useEffect(() => {
    if (open) {
      setText("");
      setIdx(0);
    }
  }, [open]);

  useEffect(() => {
    if (!open || q.length < 2) {
      setProcs({ q: "", rows: [], busy: false, error: null });
      return undefined;
    }
    const c = new AbortController();
    setProcs((p) => ({ ...p, busy: true, error: null }));
    api("processes/", { params: { search: q, host, limit: 8, ordering: "-risk_score" }, signal: c.signal })
      .then((d) => setProcs({ q, rows: arr(d?.results), busy: false, error: null }))
      .catch((e) => !c.signal.aborted && setProcs({ q, rows: [], busy: false, error: e }));
    return () => c.abort();
  }, [q, open, host]);

  const needle = text.trim().toLowerCase();
  // a match in the name beats a match in the hint, so "exit" finds Exit before "Clear history ... exited processes"
  const cmds = useMemo(() => {
    const shown = commands.filter((c) => c.when !== false && (!needle || `${c.label} ${c.hint || ""}`.toLowerCase().includes(needle)));
    if (!needle) return shown;
    const rank = (c) => {
      const label = c.label.toLowerCase();
      return label.startsWith(needle) ? 0 : label.includes(needle) ? 1 : 2;
    };
    return shown.map((c, i) => [rank(c), i, c]).sort((a, b) => a[0] - b[0] || a[1] - b[1]).map((x) => x[2]);
  }, [commands, needle]);
  const items = useMemo(
    () => [
      ...cmds.map((c) => ({ type: "cmd", key: c.id, c })),
      ...procs.rows.map((p) => ({ type: "proc", key: `p${p.id}`, p })),
    ],
    [cmds, procs.rows],
  );
  useEffect(() => setIdx((i) => Math.min(i, Math.max(0, items.length - 1))), [items.length]);
  useEffect(() => {
    list.current?.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: "nearest" });
  }, [idx]);

  const run = (it) => {
    if (!it) return;
    onClose();
    // let the dialog close and give focus back before the command moves it
    setTimeout(() => (it.type === "cmd" ? it.c.run() : onPickProcess(it.p.id)), 0);
  };

  const onKey = (e) => {
    if (e.key === "ArrowDown") (e.preventDefault(), setIdx((i) => (i + 1) % Math.max(1, items.length)));
    else if (e.key === "ArrowUp") (e.preventDefault(), setIdx((i) => (i - 1 + items.length) % Math.max(1, items.length)));
    else if (e.key === "Enter") (e.preventDefault(), run(items[idx]));
  };

  return (
    <Dialog open={open} onClose={onClose} top wide label="Search and commands">
      <div className="flex flex-col" onKeyDown={onKey}>
        <div className="flex items-center gap-2 border-b border-rule px-3">
          <input
            autoFocus
            value={text}
            onChange={(e) => (setText(e.target.value), setIdx(0))}
            placeholder="Type a command, or a process name, path or command line"
            aria-label="Search and commands"
            role="combobox"
            aria-expanded
            aria-controls="palette-list"
            className="min-w-0 flex-1 bg-transparent py-3 text-[0.9375rem] outline-none placeholder:text-graphite"
          />
          {procs.busy && <Spinner />}
          <Kbd>Esc</Kbd>
        </div>
        <ul id="palette-list" ref={list} role="listbox" className="max-h-[50vh] overflow-y-auto py-1">
          {cmds.length > 0 && <li role="presentation" className="px-3 pb-0.5 pt-1.5 text-xs text-graphite">Commands</li>}
          {items.map((it, i) => {
            const on = i === idx;
            const firstProc = it.type === "proc" && (i === 0 || items[i - 1].type !== "proc");
            return (
              <li key={it.key} role="presentation">
                {firstProc && <div className="px-3 pb-0.5 pt-2 text-xs text-graphite">Processes</div>}
                <button
                  type="button"
                  role="option"
                  aria-selected={on}
                  onMouseMove={() => setIdx(i)}
                  onClick={() => run(it)}
                  className={`flex w-full items-center gap-3 px-3 py-1.5 text-left ${on ? "bg-plate2" : ""}`}
                >
                  {it.type === "cmd" ? (
                    <>
                      <span className="flex-1">
                        {it.c.label}
                        {it.c.hint && <span className="ml-2 text-xs text-graphite">{it.c.hint}</span>}
                      </span>
                      {it.c.keys && <Kbd>{it.c.keys}</Kbd>}
                    </>
                  ) : (
                    <>
                      <RiskGauge score={it.p.risk_score} size="sm" />
                      <span className="min-w-0 flex-1">
                        <span className="font-bold">{it.p.name}</span> <span className="text-xs text-pencil tabular">PID {it.p.pid}</span>
                        <span className="block truncate font-mono text-[0.7rem] text-graphite">{midEllipsis(it.p.exe || it.p.cmdline, 70)}</span>
                      </span>
                    </>
                  )}
                </button>
              </li>
            );
          })}
          {!items.length && !procs.busy && (
            <li role="presentation" className="px-3 py-6 text-center text-[0.8125rem] text-pencil">
              {q.length >= 2 ? (procs.error ? `Search failed: ${procs.error.message}` : "Nothing matches.") : "No matching command."}
            </li>
          )}
        </ul>
      </div>
    </Dialog>
  );
}
