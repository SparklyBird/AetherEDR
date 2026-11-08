import { useEffect, useMemo, useState } from "react";
import { api } from "../lib/api";
import { bytes, hex } from "../lib/format";
import { arr, copyText } from "../lib/safe";
import { toast } from "../lib/toast";
import { Button, Empty, ErrorNote, Segmented, Spinner, Tag } from "./ui";

const CLASSES = {
  rwx: { color: "var(--redline)", label: "Writable and executable (RWX)" },
  unbacked: { color: "var(--marker)", label: "Executable, no backing file" },
  susp: { color: "var(--highlight)", label: "Executable from temp or deleted file" },
  code: { color: "var(--chalk)", label: "Executable, backed by a file" },
  data: { color: "var(--graphite)", label: "Writable data" },
  ro: { color: "var(--rule2)", label: "Read-only" },
};

function classify(r) {
  if (r.rwx) return "rwx";
  if (r.executable && r.unbacked) return "unbacked";
  if (r.executable && r.susp_path) return "susp";
  if (r.executable) return "code";
  if (r.writable) return "data";
  return "ro";
}

function HexDump({ data, base }) {
  const rows = useMemo(() => {
    const out = [];
    const src = typeof data === "string" ? data : "";
    for (let i = 0; i < src.length; i += 32) {
      const b = src.slice(i, i + 32).match(/../g) || [];
      out.push({
        off: base + i / 2,
        bytes: b,
        ascii: b.map((x) => { const c = parseInt(x, 16); return c >= 32 && c < 127 ? String.fromCharCode(c) : "·"; }).join(""),
      });
    }
    return out;
  }, [data, base]);
  return (
    <pre className="max-h-72 overflow-auto border border-rule2 bg-sheet p-3 font-mono text-[0.7rem] leading-[1.55]" aria-label="Memory bytes">
      {rows.map((r) => (
        <div key={r.off} className="flex gap-3 whitespace-pre">
          <span className="text-graphite">{r.off.toString(16).padStart(12, "0")}</span>
          <span>{r.bytes.slice(0, 8).join(" ")}{"  "}{r.bytes.slice(8).join(" ")}</span>
          <span className="text-pencil">{r.ascii}</span>
        </div>
      ))}
    </pre>
  );
}

export default function MemoryView({ processId }) {
  const [map, setMap] = useState(null);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState("exec"); // flagged | exec | all
  const [sel, setSel] = useState(null);
  const [dump, setDump] = useState(null);
  const [dumpErr, setDumpErr] = useState(null);
  const [dumping, setDumping] = useState(false);

  useEffect(() => {
    let alive = true;
    setMap(null);
    setError(null);
    setSel(null);
    setDump(null);
    api(`processes/${processId}/memory/map/`)
      .then((d) => {
        if (!alive) return;
        const regions = arr(d?.regions);
        setMap({ ...d, regions });
        setFilter(regions.length > 60 || !d?.live ? "exec" : "all");
        setSel(regions.find((r) => r.rwx || (r.executable && r.unbacked)) || null);
      })
      .catch((e) => alive && setError(e));
    return () => { alive = false; };
  }, [processId]);

  const regions = useMemo(() => {
    if (!map) return [];
    return map.regions.filter((r) => (filter === "all" ? true : filter === "flagged" ? r.flagged || r.rwx || (r.executable && r.unbacked) : r.executable || r.flagged));
  }, [map, filter]);

  const counts = useMemo(() => {
    const c = {};
    for (const r of map?.regions ?? []) c[classify(r)] = (c[classify(r)] || 0) + 1;
    return c;
  }, [map]);

  async function readBytes(r, size = 512) {
    setDumping(true);
    setDumpErr(null);
    try {
      setDump(await api(`processes/${processId}/memory/read/`, { params: { address: hex(r.start), size } }));
    } catch (e) {
      setDump(null);
      setDumpErr(e);
    } finally {
      setDumping(false);
    }
  }

  useEffect(() => {
    setDump(null);
    setDumpErr(null);
    if (sel && map?.live && sel.executable) readBytes(sel);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sel?.start, map?.live]);

  if (error) return <div className="p-4"><ErrorNote error={error} /></div>;
  if (!map) return <div className="grid place-items-center p-10"><Spinner /></div>;

  return (
    <div className="space-y-4 p-4">
      {!map.live && (
        <p className="border-l-[3px] border-marker bg-plate2 px-3 py-2 text-[0.8125rem] text-pencil">
          Live memory is unavailable. {map.reason}{map.regions.length ? " Showing the regions flagged at the last scan." : ""}
        </p>
      )}
      {!map.regions.length && !map.unreadable && <Empty title="No memory regions to show">Nothing suspicious was recorded for this process.</Empty>}
      {!map.regions.length && map.unreadable && <Empty title="Memory was not inspected">This process is a blind spot for memory checks, so no memory finding does not mean it is clean.</Empty>}

      {map.regions.length > 0 && (
        <>
          <div>
            <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
              <h3 className="text-[0.8125rem] font-bold">
                Address space <span className="font-normal text-pencil tabular">{regions.length} of {map.total ?? map.regions.length} regions</span>
              </h3>
              {map.live && (
                <Segmented size="sm" label="Which regions" value={filter} onChange={setFilter} options={[{ value: "flagged", label: "Flagged" }, { value: "exec", label: "Executable" }, { value: "all", label: "All" }]} />
              )}
            </div>
            <div className="flex max-h-44 flex-wrap content-start gap-[3px] overflow-y-auto border border-rule2 bg-sheet p-2" role="listbox" aria-label="Memory regions, ordered by address">
              {regions.map((r) => {
                const k = classify(r);
                const w = Math.min(140, Math.max(regions.length <= 16 ? 56 : 8, Math.sqrt((r.size || 4096) / 4096) * 7));
                const on = sel?.start === r.start;
                return (
                  <button
                    key={r.start}
                    role="option"
                    aria-selected={on}
                    aria-label={`${hex(r.start)}, ${bytes(r.size)}, ${CLASSES[k].label}`}
                    onClick={() => setSel(r)}
                    title={`${hex(r.start)}  ${bytes(r.size)}  ${r.protect || r.perms}`}
                    style={{ width: w, background: CLASSES[k].color, opacity: on ? 1 : k === "ro" || k === "data" ? 0.55 : 0.92 }}
                    className={`h-6 rounded-[1px] ${on ? "outline outline-2 outline-offset-1 outline-ink" : ""}`}
                  />
                );
              })}
              {!regions.length && <p className="p-2 text-xs text-pencil">No regions in this filter.</p>}
            </div>
            <ul className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-pencil">
              {Object.entries(CLASSES).map(([k, c]) => counts[k] > 0 && (
                <li key={k} className="flex items-center gap-1.5">
                  <span className="size-2.5" style={{ background: c.color }} aria-hidden />
                  {c.label} <span className="text-graphite tabular">{counts[k]}</span>
                </li>
              ))}
            </ul>
          </div>

          {sel && (
            <div className="space-y-3 border border-rule2 bg-plate2 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-[0.8125rem] font-bold">{hex(sel.start)}–{hex(sel.start + sel.size)}</span>
                <Tag>{bytes(sel.size)}</Tag>
                <Tag tone={CLASSES[classify(sel)].color}>{sel.protect || sel.perms}</Tag>
                {sel.header && <Tag tone="var(--redline)" title="Executable image header found in this region">{sel.header} header</Tag>}
                {sel.entropy != null && <Tag title="Shannon entropy of the first 4 KB. Above 7.2 suggests packed or encrypted code.">entropy {sel.entropy}</Tag>}
              </div>
              <p className="break-all font-mono text-xs text-pencil">{sel.path || `${sel.kind} memory, no file behind it`}</p>
              {map.live && sel.executable && (
                <div className="space-y-2">
                  {dumping && <Spinner />}
                  <ErrorNote error={dumpErr} />
                  {dump && <HexDump data={dump.hex} base={parseInt(dump.address, 16) || sel.start} />}
                  <div className="flex gap-2">
                    {dump && sel.size > dump.size && dump.size < 4096 && <Button size="sm" onClick={() => readBytes(sel, 4096)}>Read up to 4 KB</Button>}
                    {dump && <Button size="sm" variant="ghost" onClick={async () => toast({ title: (await copyText(dump.hex)) ? "Hex copied" : "Copy failed", tone: "good", ms: 2000 })}>Copy hex</Button>}
                  </div>
                </div>
              )}
              {map.live && !sel.executable && <p className="text-xs text-pencil">Byte inspection is limited to executable regions so data heaps (which can hold credentials) are never dumped.</p>}
            </div>
          )}
        </>
      )}
    </div>
  );
}
