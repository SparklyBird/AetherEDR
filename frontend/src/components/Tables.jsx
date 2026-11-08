import { useMemo, useState } from "react";
import { api } from "../lib/api";
import { midEllipsis, plural, stamp, timeAgo } from "../lib/format";
import { useDebounced, usePolled } from "../lib/hooks";
import { arr, saveBlob, toCsv } from "../lib/safe";
import { useSettings } from "../lib/settings";
import { toast } from "../lib/toast";
import { Button, Empty, ErrorPanel, Input, RiskGauge, Select, Spinner, Tag } from "./ui";

function Toolbar({ children, right }) {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2 border-b border-rule2 bg-plate px-4 py-2">
      {children}
      <span className="ml-auto flex items-center gap-3 text-xs text-pencil">{right}</span>
    </div>
  );
}

function Check({ checked, onChange, children }) {
  return (
    <label className="flex cursor-pointer items-center gap-1.5 text-[0.8125rem] text-pencil">
      <input type="checkbox" className="accent-[var(--ink)]" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      {children}
    </label>
  );
}

/** Sortable column header. `sort` = {key, dir}. */
function Th({ label, k, sort, onSort, className = "" }) {
  const on = sort.key === k;
  return (
    <th scope="col" aria-sort={on ? (sort.dir === "asc" ? "ascending" : "descending") : "none"} className={`px-2 py-2 font-medium ${className}`}>
      {k ? (
        <button type="button" onClick={() => onSort(k)} className={`inline-flex items-center gap-1 hover:text-ink ${on ? "text-ink" : ""}`}>
          {label}
          <span aria-hidden className="text-[0.6rem]">{on ? (sort.dir === "asc" ? "▲" : "▼") : ""}</span>
        </button>
      ) : (
        label
      )}
    </th>
  );
}

function download(name, columns, rows) {
  try {
    saveBlob(new Blob([toCsv(columns, rows)], { type: "text/csv;charset=utf-8" }), `${name}-${new Date().toISOString().slice(0, 16).replace(/[:T-]/g, "")}.csv`);
    toast({ title: "Table saved", body: `${plural(rows.length, "row")} as CSV.`, tone: "good", ms: 3000 });
  } catch (e) {
    toast({ title: "Could not save the table", body: String(e?.message || e), tone: "bad" });
  }
}

const geo = (c) => (c.scope === "public" ? [c.country, c.asn ? `AS${c.asn}` : "", c.as_org].filter(Boolean).join(" ") || "no GeoIP data" : c.scope);

export function ProcessTable({ host, selectedId, onSelect, rev }) {
  const s = useSettings();
  const [search, setSearch] = useState("");
  const [alive, setAlive] = useState(true);
  const [flagged, setFlagged] = useState(false);
  const [limit, setLimit] = useState(200);
  const [sort, setSort] = useState({ key: "risk_score", dir: "desc" });
  const q = useDebounced(search);
  const ordering = `${sort.dir === "desc" ? "-" : ""}${sort.key}`;

  const { data, error, loading, stale, reload } = usePolled(
    (signal) => api("processes/", { params: { host, search: q, alive: alive ? 1 : undefined, min_score: flagged ? 1 : undefined, limit, ordering }, signal }),
    [host, q, alive, flagged, limit, ordering, rev],
    { interval: s.refresh },
  );
  const rows = arr(data?.results);
  const onSort = (k) => setSort((o) => (o.key === k ? { key: k, dir: o.dir === "desc" ? "asc" : "desc" } : { key: k, dir: k === "name" ? "asc" : "desc" }));

  return (
    <div className="flex h-full min-h-0 flex-col bg-sheet">
      <Toolbar
        right={
          <>
            {stale && <span className="text-marker">Showing last update</span>}
            {loading && <Spinner />}
            <span className="tabular">{data ? `${rows.length} of ${data.count ?? rows.length}` : ""}</span>
            <Button size="sm" variant="ghost" disabled={!rows.length} onClick={() => download("AetherEDR-processes", [
              { label: "Risk", value: "risk_score" }, { label: "Name", value: "name" }, { label: "PID", value: "pid" }, { label: "Host", value: "host_name" }, { label: "User", value: "username" },
              { label: "Path", value: "exe" }, { label: "Command", value: "cmdline" }, { label: "SHA-256", value: "sha256" }, { label: "Started", value: "started_at" },
              { label: "Running", value: (r) => (r.alive ? "yes" : "no") }, { label: "Top finding", value: "top_finding" }, { label: "Outbound sockets", value: "net_out" },
            ], rows)}>Save CSV</Button>
          </>
        }
      >
        <Input type="search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Name, path, command or user" aria-label="Search processes" className="w-72 max-w-full" />
        <Check checked={alive} onChange={setAlive}>Running only</Check>
        <Check checked={flagged} onChange={setFlagged}>Flagged only</Check>
        <label className="flex items-center gap-1.5 text-[0.8125rem] text-pencil">
          Rows
          <Select value={limit} onChange={(e) => setLimit(+e.target.value)} className="!py-0.5 text-xs">
            {[100, 200, 500, 1000].map((n) => <option key={n}>{n}</option>)}
          </Select>
        </label>
      </Toolbar>
      <ErrorPanel error={error && !data ? error : null} onRetry={reload} title="Could not load processes" />
      <div className="min-h-0 flex-1 overflow-auto">
        {!data && !error ? (
          <div className="grid place-items-center p-10"><Spinner /></div>
        ) : !rows.length && data ? (
          <Empty title="No processes match" action={(search || flagged || !alive) && <Button size="sm" onClick={() => (setSearch(""), setFlagged(false), setAlive(true))}>Clear filters</Button>}>Try a shorter search.</Empty>
        ) : (
          <table className="w-full min-w-[760px] text-left text-[0.8125rem]">
            <thead className="sticky top-0 z-10 bg-plate text-xs text-pencil shadow-[0_1px_0_var(--rule2)]">
              <tr>
                <Th label="Risk" k="risk_score" sort={sort} onSort={onSort} className="w-20 pl-4" />
                <Th label="Process" k="name" sort={sort} onSort={onSort} />
                <Th label="PID" k="pid" sort={sort} onSort={onSort} />
                <Th label="User" sort={sort} />
                <Th label="Started" k="started_at" sort={sort} onSort={onSort} />
                <Th label="Sockets" k="net_out" sort={sort} onSort={onSort} />
                <Th label="Memory" k="last_rss" sort={sort} onSort={onSort} />
              </tr>
            </thead>
            <tbody>
              {rows.map((p) => (
                <tr
                  key={p.id}
                  tabIndex={0}
                  aria-selected={selectedId === p.id}
                  onClick={() => onSelect(p.id)}
                  onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), onSelect(p.id))}
                  className={`cursor-pointer border-b border-rule hover:bg-plate ${selectedId === p.id ? "bg-plate2" : ""} ${p.alive ? "" : "opacity-55"}`}
                >
                  <td className="py-1.5 pl-4 pr-2"><RiskGauge score={p.risk_score} size="sm" /></td>
                  <td className="px-2 py-1.5">
                    <span className="font-bold">{p.name}</span>
                    <div className="font-mono text-[0.7rem] text-graphite" title={p.exe}>{midEllipsis(p.exe, 64)}</div>
                    {p.top_finding && <div className="text-xs italic text-redline">{p.top_finding}</div>}
                  </td>
                  <td className="px-2 py-1.5 tabular text-pencil">{p.pid}</td>
                  <td className="px-2 py-1.5 text-pencil">{midEllipsis(p.username, 22)}</td>
                  <td className="whitespace-nowrap px-2 py-1.5 text-pencil" title={stamp(p.started_at)}>{timeAgo(p.started_at)}</td>
                  <td className="px-2 py-1.5 tabular text-pencil">{p.net_out || ""}{p.net_listen ? ` +${p.net_listen} listening` : ""}</td>
                  <td className="px-2 py-1.5">
                    {p.rwx_regions > 0 && <Tag tone="var(--redline)">RWX {p.rwx_regions}</Tag>} {p.unbacked_exec > 0 && <Tag tone="var(--marker)">unbacked {p.unbacked_exec}</Tag>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

export function NetworkTable({ host, onSelect, rev }) {
  const s = useSettings();
  const [search, setSearch] = useState("");
  const [scope, setScope] = useState("public");
  const [direction, setDirection] = useState("outbound");
  const [sort, setSort] = useState({ key: "first_seen", dir: "desc" });
  const q = useDebounced(search);

  const { data, error, loading, stale, reload } = usePolled(
    (signal) => api("connections/", { params: { host, search: q, direction: direction || undefined, scope: scope || undefined, limit: 500 }, signal }),
    [host, q, scope, direction, rev],
    { interval: s.refresh },
  );
  const rows = useMemo(() => {
    const list = [...arr(data?.results)];
    const val = { process_name: (c) => String(c.process_name).toLowerCase(), raddr: (c) => `${c.raddr}:${c.rport}`, geo: (c) => geo(c).toLowerCase(), first_seen: (c) => c.first_seen, entropy: (c) => c.entropy ?? -1 }[sort.key];
    if (val) list.sort((a, b) => (val(a) < val(b) ? -1 : val(a) > val(b) ? 1 : 0) * (sort.dir === "asc" ? 1 : -1));
    return list;
  }, [data, sort]);
  const onSort = (k) => setSort((o) => (o.key === k ? { key: k, dir: o.dir === "desc" ? "asc" : "desc" } : { key: k, dir: k === "first_seen" || k === "entropy" ? "desc" : "asc" }));

  return (
    <div className="flex h-full min-h-0 flex-col bg-sheet">
      <Toolbar
        right={
          <>
            {stale && <span className="text-marker">Showing last update</span>}
            {loading && <Spinner />}
            <span className="tabular">{data ? `${rows.length} of ${data.count ?? rows.length}` : ""}</span>
            <Button size="sm" variant="ghost" disabled={!rows.length} onClick={() => download("AetherEDR-connections", [
              { label: "Process", value: "process_name" }, { label: "PID", value: "pid" }, { label: "Protocol", value: "proto" }, { label: "Remote", value: (c) => `${c.raddr}:${c.rport}` },
              { label: "Hostname", value: "hostname" }, { label: "Entropy", value: "entropy" }, { label: "Network", value: geo }, { label: "First seen", value: "first_seen" },
            ], rows)}>Save CSV</Button>
          </>
        }
      >
        <Input type="search" value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Address, process or network" aria-label="Search connections" className="w-72 max-w-full" />
        <label className="flex items-center gap-1.5 text-[0.8125rem] text-pencil">
          Destinations
          <Select value={scope} onChange={(e) => setScope(e.target.value)} className="!py-0.5 text-xs">
            <option value="public">Internet</option>
            <option value="">Everything</option>
            <option value="private">Local network</option>
          </Select>
        </label>
        <label className="flex items-center gap-1.5 text-[0.8125rem] text-pencil">
          Direction
          <Select value={direction} onChange={(e) => setDirection(e.target.value)} className="!py-0.5 text-xs">
            <option value="outbound">Outbound</option>
            <option value="listen">Listening</option>
            <option value="">Both</option>
          </Select>
        </label>
      </Toolbar>
      <ErrorPanel error={error && !data ? error : null} onRetry={reload} title="Could not load connections" />
      <div className="min-h-0 flex-1 overflow-auto">
        {!data && !error ? (
          <div className="grid place-items-center p-10"><Spinner /></div>
        ) : !rows.length && data ? (
          <Empty title="No connections match">Sockets appear here once a process connects.</Empty>
        ) : (
          <table className="w-full min-w-[700px] text-left text-[0.8125rem]">
            <thead className="sticky top-0 z-10 bg-plate text-xs text-pencil shadow-[0_1px_0_var(--rule2)]">
              <tr>
                <Th label="Process" k="process_name" sort={sort} onSort={onSort} className="pl-4" />
                <Th label="Destination" k="raddr" sort={sort} onSort={onSort} />
                <Th label="Network" k="geo" sort={sort} onSort={onSort} />
                <Th label="Name entropy" k="entropy" sort={sort} onSort={onSort} />
                <Th label="Seen" k="first_seen" sort={sort} onSort={onSort} />
              </tr>
            </thead>
            <tbody>
              {rows.map((c) => (
                <tr key={c.id} tabIndex={0} onClick={() => onSelect(c.process)} onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && (e.preventDefault(), onSelect(c.process))} className="cursor-pointer border-b border-rule hover:bg-plate">
                  <td className="py-1.5 pl-4 pr-2"><span className="font-bold">{c.process_name}</span> <span className="text-xs text-pencil tabular">{c.pid}</span></td>
                  <td className="px-2 py-1.5 font-mono text-xs">
                    {c.direction === "listen" ? `listening :${c.lport}` : `${c.raddr}:${c.rport}`} <span className="text-graphite">{c.proto}</span>
                    {c.hostname && <div className="text-pencil">{c.hostname}</div>}
                  </td>
                  <td className="px-2 py-1.5 text-xs text-pencil">{geo(c)}</td>
                  <td className="px-2 py-1.5 text-xs tabular text-pencil">{c.entropy ?? ""}</td>
                  <td className="whitespace-nowrap px-2 py-1.5 text-xs text-pencil" title={stamp(c.first_seen)}>{timeAgo(c.first_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
