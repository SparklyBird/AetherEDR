// fetch wrapper. The API key comes in once through the URL fragment (#key=...), gets moved to
// sessionStorage and is removed from the address bar.
import { toast } from "./toast";

const STORE = "aether.key";
const TIMEOUT_MS = 20000;

export function initKey() {
  try {
    const m = location.hash.match(/key=([^&]+)/);
    if (m) {
      sessionStorage.setItem(STORE, decodeURIComponent(m[1]));
      history.replaceState(null, "", location.pathname + location.search);
    }
    return sessionStorage.getItem(STORE) || "";
  } catch {
    return "";
  }
}

export const getKey = () => {
  try {
    return sessionStorage.getItem(STORE) || "";
  } catch {
    return "";
  }
};

export const setKey = (k) => {
  try {
    sessionStorage.setItem(STORE, k.trim());
  } catch {
    /* storage blocked: the key lives only until reload */
  }
};

export class ApiError extends Error {
  constructor(status, body) {
    super(typeof body === "string" ? summarize(body, status) : flatten(body) || `HTTP ${status}`);
    this.status = status;
    this.body = body;
  }
}

/** Server not reachable (stopped, restarting, offline or too slow). */
export class NetworkError extends Error {
  constructor(cause, timedOut = false) {
    super(timedOut ? "AetherEDR took too long to answer." : "Can't reach AetherEDR. Check that it is still running.");
    this.cause = cause;
    this.network = true;
    this.timedOut = timedOut;
  }
}

function summarize(text, status) {
  // don't show raw HTML error pages from a proxy or a crashed server
  if (/^\s*</.test(text)) return `The server answered with an error page (HTTP ${status}).`;
  return text.slice(0, 300) || `HTTP ${status}`;
}

function flatten(b) {
  if (!b) return "";
  if (typeof b === "string") return b;
  if (Array.isArray(b)) return b.map(flatten).join(" ");
  if (typeof b === "object") return Object.entries(b).map(([k, v]) => (k === "detail" ? flatten(v) : `${k}: ${flatten(v)}`)).join("; ");
  return String(b);
}

export function qs(params = {}) {
  const u = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") u.set(k, v);
  const s = u.toString();
  return s ? `?${s}` : "";
}

async function once(path, { method, body, params, signal, timeout }) {
  const ctrl = new AbortController();
  let timedOut = false;
  const timer = setTimeout(() => ((timedOut = true), ctrl.abort()), timeout);
  const onAbort = () => ctrl.abort();
  signal?.addEventListener("abort", onAbort);
  try {
    return await fetch(`/api/${path}${qs(params)}`, {
      method,
      signal: ctrl.signal,
      headers: { "X-Aether-Key": getKey(), ...(body ? { "Content-Type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    if (signal?.aborted) throw e; // the caller cancelled: not a failure
    throw new NetworkError(e, timedOut);
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", onAbort);
  }
}

export async function api(path, { method = "GET", body, params, blob = false, text = false, signal, timeout = TIMEOUT_MS } = {}) {
  let res;
  try {
    res = await once(path, { method, body, params, signal, timeout });
  } catch (e) {
    // retry reads once, covers a restart or a dropped keep-alive connection
    if (method === "GET" && e instanceof NetworkError && !e.timedOut) {
      await new Promise((r) => setTimeout(r, 400));
      if (signal?.aborted) throw e;
      res = await once(path, { method, body, params, signal, timeout });
    } else throw e;
  }
  if (res.status === 401) {
    window.dispatchEvent(new Event("aether:unauthorized"));
    throw new ApiError(401, "Invalid or missing API key");
  }
  if (!res.ok) {
    // read the body once, a failed res.json() leaves nothing for res.text()
    const raw = await res.text().catch(() => "");
    let data = raw;
    try {
      data = JSON.parse(raw);
    } catch {
      /* not JSON: keep the text, ApiError turns HTML error pages into a plain sentence */
    }
    throw new ApiError(res.status, data);
  }
  if (res.status === 204) return null;
  try {
    return blob ? await res.blob() : text ? await res.text() : await res.json();
  } catch {
    throw new ApiError(res.status, "The server sent a response the console could not read.");
  }
}

/** SSE over fetch so the key goes in a header and not in the URL. */
export function openAlertStream({ onAlert, onStats, onState, params }) {
  let stop = false;
  let ctrl = null;
  let lastId = 0;
  let delay = 1000;

  async function run() {
    while (!stop) {
      ctrl = new AbortController();
      try {
        onState?.("connecting");
        const res = await fetch(`/api/alerts/stream/${qs({ ...params, last_id: lastId || undefined })}`, {
          headers: { "X-Aether-Key": getKey(), Accept: "text/event-stream" },
          signal: ctrl.signal,
        });
        if (res.status === 401) {
          window.dispatchEvent(new Event("aether:unauthorized"));
          return;
        }
        if (!res.ok || !res.body) throw new Error(`stream ${res.status}`);
        onState?.("live");
        delay = 1000;
        const reader = res.body.getReader();
        const dec = new TextDecoder();
        let buf = "";
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          let i;
          while ((i = buf.indexOf("\n\n")) >= 0) {
            const frame = buf.slice(0, i);
            buf = buf.slice(i + 2);
            let ev = "message";
            let data = "";
            for (const line of frame.split("\n")) {
              if (line.startsWith("event:")) ev = line.slice(6).trim();
              else if (line.startsWith("data:")) data += line.slice(5).trim();
            }
            if (!data) continue;
            try {
              const obj = JSON.parse(data);
              if (ev === "alert") {
                lastId = Math.max(lastId, obj.id);
                onAlert?.(obj);
              } else if (ev === "stats") onStats?.(obj);
            } catch {
              /* ignore malformed frame */
            }
          }
        }
      } catch (e) {
        if (stop) return;
      }
      if (stop) return;
      onState?.("offline");
      await new Promise((r) => setTimeout(r, delay));
      delay = Math.min(delay * 2, 15000);
    }
  }
  run();
  return () => {
    stop = true;
    ctrl?.abort();
  };
}

function stamp() {
  return new Date().toISOString().slice(0, 16).replace(/[:T]/g, "");
}

export async function downloadFile(path, params, filename) {
  const blob = await api(path, { params, blob: true, timeout: 120000 });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 5000);
}

export const downloadReport = ({ type, hours, host }) =>
  downloadFile("reports/export/", { type, hours, host }, `AetherEDR-Security-Report-${stamp()}.${type}`);

export const downloadAlerts = ({ type, hours, host, status, severity }) =>
  downloadFile("alerts/export/", { type, hours, host, status, severity }, `AetherEDR-alerts-${stamp()}.${type}`);

export const downloadProcesses = ({ type, host, minScore, alive }) =>
  downloadFile("processes/export/", { type, host, min_score: minScore, alive }, `AetherEDR-flagged-processes-${stamp()}.${type}`);

/** Toast for a failed user action. Failed reads stay quiet, their panels show the error. */
export function explain(e, title = "That did not work") {
  toast({ title, body: e?.message || String(e), tone: "bad", ms: 7000 });
}
