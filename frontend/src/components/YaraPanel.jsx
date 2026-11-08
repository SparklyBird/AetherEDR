import { useEffect, useRef, useState } from "react";
import { api } from "../lib/api";
import { SEV, bytes, timeAgo } from "../lib/format";
import { Button, ErrorNote, Spinner, Tag } from "./ui";

const SCOPES = [
  ["flagged", "Flagged regions", "Only regions the collector marked (RWX or unbacked executable). Fastest."],
  ["executable", "All executable memory", "Every executable region, including loaded libraries."],
  ["all", "Everything readable", "Whole address space up to the size cap. Slow."],
];

function JobResult({ job }) {
  const running = job.status === "queued" || job.status === "running";
  const matches = Array.isArray(job.matches) ? job.matches : [];
  return (
    <div className="space-y-2 border border-rule2 bg-plate2 p-3">
      <div className="flex flex-wrap items-center gap-2 text-[0.8125rem]">
        {running ? <Spinner /> : null}
        <span className="font-bold">{running ? "Scanning" : job.status === "done" ? "Scan finished" : "Scan failed"}</span>
        <span className="text-xs text-pencil">{timeAgo(job.requested_at)}{job.auto ? ", started automatically" : ""}</span>
        {job.status === "done" && <Tag>{job.regions_scanned} regions, {bytes(job.bytes_scanned)}</Tag>}
      </div>
      {job.error && <ErrorNote error={job.error} />}
      {job.status === "done" && !matches.length && <p className="text-[0.8125rem] text-ok">No signature matched.</p>}
      <ul className="space-y-2">
        {matches.map((m, i) => {
          const sev = m.meta?.severity || "medium";
          return (
            <li key={i} className="border-l-[3px] bg-sheet p-2.5" style={{ borderColor: SEV[sev]?.color }}>
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-bold" style={{ color: SEV[sev]?.color }}>{m.rule}</span>
                <Tag>{m.source === "memory" ? "in memory" : "on disk"}</Tag>
                {m.meta?.technique && <Tag>{m.meta.technique}</Tag>}
              </div>
              {m.meta?.description && <p className="mt-1 text-[0.8125rem] text-pencil">{m.meta.description}</p>}
              {Array.isArray(m.strings) && m.strings.length > 0 && (
                <p className="mt-1.5 break-all font-mono text-[0.7rem] text-pencil">{m.strings.slice(0, 3).map((s) => `${s.id} at ${s.address}`).join(",  ")}</p>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export default function YaraPanel({ process, onFinished }) {
  const [scope, setScope] = useState("flagged");
  const [includeFile, setIncludeFile] = useState(true);
  const [custom, setCustom] = useState("");
  const [validation, setValidation] = useState(null);
  const [job, setJob] = useState(null);
  const [error, setError] = useState(null);
  const timer = useRef(null);
  const alive = useRef(true);

  const past = (process.yara_jobs || []).filter((j) => !job || j.id !== job.id);

  useEffect(() => {
    alive.current = true;
    return () => { alive.current = false; clearTimeout(timer.current); };
  }, []);

  function poll(id, fails = 0) {
    api(`yara/${id}/`)
      .then((j) => {
        if (!alive.current) return;
        setJob(j);
        if (j.status === "queued" || j.status === "running") timer.current = setTimeout(() => poll(id), 1200);
        else onFinished?.();
      })
      .catch((e) => {
        if (!alive.current) return;
        if (fails < 3) timer.current = setTimeout(() => poll(id, fails + 1), 2000);
        else setError(e);
      });
  }

  async function run() {
    setError(null);
    setJob(null);
    try {
      const j = await api(`processes/${process.id}/yara-scan/`, { method: "POST", body: { scope, include_file: includeFile, custom_rules: custom } });
      setJob(j);
      poll(j.id);
    } catch (e) {
      setError(e);
    }
  }

  async function validate() {
    try {
      setValidation(await api("yara/validate/", { method: "POST", body: { rules: custom } }));
    } catch (e) {
      setValidation({ valid: false, error: e.message });
    }
  }

  const busy = job && (job.status === "queued" || job.status === "running");

  if (process.yara_available === false) {
    return (
      <div className="space-y-2 p-4">
        <p className="font-bold">YARA is not installed on this server</p>
        <p className="text-[0.8125rem] text-pencil">
          Everything else works. To enable memory signature scans, run <code className="font-mono text-ink">pip install -r requirements-yara.txt</code> and restart. On Windows this needs Python 3.12 or 3.13, or the Microsoft C++ Build Tools.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4 p-4">
      <fieldset className="space-y-1.5">
        <legend className="mb-1 text-[0.8125rem] font-bold">What to scan</legend>
        {SCOPES.map(([v, l, d]) => (
          <label key={v} className={`flex cursor-pointer items-start gap-2.5 border p-2.5 ${scope === v ? "border-ink bg-plate2" : "border-rule hover:border-rule2"}`}>
            <input type="radio" name="yara-scope" checked={scope === v} onChange={() => setScope(v)} className="mt-1 accent-[var(--ink)]" />
            <span>
              <span className="block text-[0.8125rem] font-medium">{l}</span>
              <span className="block text-xs text-pencil">{d}</span>
            </span>
          </label>
        ))}
        <label className="flex cursor-pointer items-center gap-2 pt-1 text-[0.8125rem] text-pencil">
          <input type="checkbox" checked={includeFile} onChange={(e) => setIncludeFile(e.target.checked)} className="accent-[var(--ink)]" />
          Also scan the executable file on disk
        </label>
      </fieldset>

      <details className="border border-rule">
        <summary className="cursor-pointer px-3 py-2 text-[0.8125rem] font-medium">Add your own YARA rules</summary>
        <div className="space-y-2 p-3 pt-1">
          <textarea
            value={custom}
            onChange={(e) => (setCustom(e.target.value), setValidation(null))}
            rows={7}
            spellCheck={false}
            placeholder={'rule my_marker {\n  strings: $a = "example" ascii\n  condition: $a\n}'}
            className="w-full resize-y border border-rule2 bg-sheet p-2.5 font-mono text-xs outline-none focus:border-chalk"
            aria-label="Custom YARA rules"
          />
          <div className="flex items-center gap-2">
            <Button size="sm" onClick={validate} disabled={!custom.trim()}>Check syntax</Button>
            {validation && <span className={`text-xs ${validation.valid ? "text-ok" : "text-redline"}`}>{validation.valid ? `Valid: ${(validation.rules || []).join(", ")}` : validation.error}</span>}
          </div>
        </div>
      </details>

      <div className="flex items-center gap-3">
        <Button variant="primary" onClick={run} disabled={busy || !process.alive}>
          {busy && <Spinner />} Scan process memory
        </Button>
        {!process.alive && <span className="text-xs text-pencil">This process has exited.</span>}
      </div>
      <ErrorNote error={error} />
      {job && <JobResult job={job} />}
      {past.length > 0 && (
        <div className="space-y-2">
          <h3 className="text-[0.8125rem] font-bold">Earlier scans</h3>
          {past.map((j) => <JobResult key={j.id} job={j} />)}
        </div>
      )}
    </div>
  );
}
