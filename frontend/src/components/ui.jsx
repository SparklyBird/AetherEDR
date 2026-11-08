import { useEffect, useId, useLayoutEffect, useRef, useState } from "react";
import { cloudPath } from "../lib/cloud";
import { SEV, colorForScore, sevForScore } from "../lib/format";

/* ---------- identity ---------- */
export function Mark({ size = 24 }) {
  // small process tree with one node circled
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden>
      <path d="M5 16H11M11 16V8H18M11 16V24H18" stroke="var(--pencil)" strokeWidth="1.4" fill="none" />
      <circle cx="5" cy="16" r="2.2" fill="var(--ink)" />
      <circle cx="18" cy="8" r="2.2" fill="var(--ink)" />
      <circle cx="18" cy="24" r="2.2" fill="var(--redline)" />
      <path d={cloudPath(18, 24, 6.2, 7, 8)} stroke="var(--redline)" strokeWidth="1.3" fill="none" />
      <path d="M24 24H29" stroke="var(--pencil)" strokeWidth="1.4" />
    </svg>
  );
}

/* ---------- risk ---------- */
/** Risk 0-100 as a gauge plus the number. Only coloured when there is something to flag. */
export function RiskGauge({ score = 0, size = "md", className = "" }) {
  const s = Math.max(0, Math.min(100, Math.round(Number(score) || 0)));
  const h = size === "lg" ? 52 : size === "sm" ? 24 : 38;
  const col = colorForScore(s);
  const sev = sevForScore(s);
  return (
    <span className={`inline-flex shrink-0 items-center gap-1.5 ${className}`} role="img" aria-label={`Risk ${s} of 100${sev !== "none" ? `, ${sev}` : ""}`}>
      <svg width="7" height={h} viewBox={`0 0 7 ${h}`} aria-hidden>
        <rect x="0.5" y="0.5" width="6" height={h - 1} fill="none" stroke="var(--rule2)" />
        {s > 0 && <rect x="1.5" y={h - 1 - ((h - 3) * s) / 100} width="4" height={((h - 3) * s) / 100} fill={col} />}
        {[0.25, 0.5, 0.75].map((t) => (
          <line key={t} x1="0.5" x2="3" y1={h * t} y2={h * t} stroke="var(--rule2)" />
        ))}
      </svg>
      <span className={`font-bold tabular leading-none ${size === "lg" ? "text-3xl" : size === "sm" ? "text-sm" : "text-xl"}`} style={{ color: s >= 40 ? col : "var(--ink)" }}>
        {s}
      </span>
    </span>
  );
}

export function SevDot({ sev, className = "" }) {
  return <span className={`inline-block size-2 ${className}`} style={{ background: SEV[sev]?.color ?? "var(--graphite)", borderRadius: 1 }} aria-hidden />;
}

/* ---------- small parts ---------- */
export function Tag({ children, tone, title, mono = false, className = "" }) {
  return (
    <span
      title={title}
      style={tone ? { color: tone, borderColor: `color-mix(in srgb, ${tone} 55%, transparent)` } : undefined}
      className={`inline-flex items-center gap-1 rounded-xs border px-1.5 py-px text-xs leading-snug ${tone ? "" : "border-rule2 text-pencil"} ${mono ? "font-mono text-[0.7rem]" : ""} ${className}`}
    >
      {children}
    </span>
  );
}

export function Kbd({ children }) {
  return <kbd className="rounded-xs border border-rule2 bg-plate px-1 font-mono text-[0.68rem] leading-5 text-pencil">{children}</kbd>;
}

const BTN = {
  default: "border border-rule2 hover:bg-plate2 active:bg-rule",
  primary: "border border-ink bg-ink text-sheet hover:opacity-90",
  ghost: "border border-transparent hover:bg-plate2 text-pencil hover:text-ink",
  danger: "border border-redline text-redline hover:bg-[color-mix(in_srgb,var(--redline)_14%,transparent)]",
};
export function Button({ children, variant = "default", size = "md", className = "", ...p }) {
  return (
    <button
      type="button"
      {...p}
      className={`inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-45 ${size === "sm" ? "px-2 py-1 text-xs" : "px-3 py-1.5 text-[0.8125rem]"} ${BTN[variant]} ${className}`}
    >
      {children}
    </button>
  );
}

export function Spinner({ className = "" }) {
  return <span role="status" aria-label="Loading" className={`inline-block size-3.5 animate-spin rounded-full border-2 border-dashed border-pencil ${className}`} />;
}

export function Segmented({ options, value, onChange, label, size = "md", className = "" }) {
  return (
    <div role="group" aria-label={label} className={`inline-flex overflow-hidden rounded-sm border border-rule2 ${className}`}>
      {options.map((o, i) => {
        const on = value === o.value;
        return (
          <button
            key={String(o.value)}
            type="button"
            aria-pressed={on}
            onClick={() => onChange(o.value)}
            title={o.title}
            className={`${size === "sm" ? "px-2 py-1 text-xs" : "px-2.5 py-1.5 text-[0.8125rem]"} ${i ? "border-l border-rule2" : ""} ${on ? "bg-ink font-medium text-sheet" : "text-pencil hover:bg-plate2 hover:text-ink"}`}
          >
            {o.label}
            {o.count != null && <span className={`ml-1.5 tabular ${on ? "opacity-70" : "text-graphite"}`}>{o.count}</span>}
          </button>
        );
      })}
    </div>
  );
}

export function Switch({ checked, onChange, label, hint, id }) {
  const gen = useId();
  const sid = id || gen;
  return (
    <label htmlFor={sid} className="flex cursor-pointer items-start justify-between gap-4 py-1.5">
      <span className="min-w-0">
        <span className="block text-[0.8125rem]">{label}</span>
        {hint && <span className="block text-xs text-graphite">{hint}</span>}
      </span>
      <span className="relative mt-0.5 shrink-0">
        <input id={sid} type="checkbox" role="switch" checked={checked} onChange={(e) => onChange(e.target.checked)} className="peer sr-only" />
        <span className="block h-4 w-8 rounded-xs border border-rule2 bg-sheet peer-checked:border-ink peer-checked:bg-ink peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-chalk" />
        <span className="pointer-events-none absolute left-0.5 top-0.5 size-3 rounded-[1px] bg-pencil transition-transform peer-checked:translate-x-4 peer-checked:bg-sheet" />
      </span>
    </label>
  );
}

export const inputCls =
  "rounded-sm border border-rule2 bg-sheet px-2.5 py-1.5 text-[0.8125rem] text-ink placeholder:text-graphite outline-none focus:border-chalk";

export function Input({ className = "", ...p }) {
  return <input {...p} className={`${inputCls} ${className}`} />;
}

export function Select({ children, className = "", ...p }) {
  return (
    <select {...p} className={`${inputCls} pr-6 ${className}`}>
      {children}
    </select>
  );
}

/* ---------- states ---------- */
export function Empty({ title, children, action, className = "" }) {
  return (
    <div className={`mx-auto my-10 flex max-w-sm flex-col items-center gap-2 rounded-sm border border-dashed border-rule2 px-6 py-9 text-center ${className}`}>
      <p className="font-bold">{title}</p>
      {children && <p className="text-pencil">{children}</p>}
      {action}
    </div>
  );
}

export function ErrorPanel({ error, onRetry, title = "Could not load this", compact = false }) {
  if (!error) return null;
  const down = error.network;
  return (
    <div role="alert" className={`flex items-start gap-3 border-l-[3px] border-redline bg-[color-mix(in_srgb,var(--redline)_9%,transparent)] ${compact ? "px-3 py-2" : "m-3 px-3.5 py-3"}`}>
      <div className="min-w-0 flex-1">
        <p className="font-bold text-redline">{down ? "Lost contact with AetherEDR" : title}</p>
        <p className="break-words text-[0.8125rem] text-pencil">{String(error.message || error)}</p>
      </div>
      {onRetry && (
        <Button size="sm" onClick={onRetry}>
          Try again
        </Button>
      )}
    </div>
  );
}

export function ErrorNote({ error }) {
  if (!error) return null;
  return (
    <p role="alert" className="border-l-[3px] border-redline bg-[color-mix(in_srgb,var(--redline)_9%,transparent)] px-3 py-2 text-[0.8125rem] text-redline">
      {String(error.message || error)}
    </p>
  );
}

/* ---------- tabs ---------- */
export function Tabs({ tabs, value, onChange, label, className = "" }) {
  return (
    <div role="tablist" aria-label={label} className={`flex gap-0.5 overflow-x-auto border-b border-rule px-2 ${className}`}>
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          aria-selected={value === t.id}
          onClick={() => onChange(t.id)}
          className={`-mb-px shrink-0 border-b-2 px-2.5 py-2 text-[0.8125rem] font-medium ${value === t.id ? "border-ink text-ink" : "border-transparent text-pencil hover:text-ink"}`}
        >
          {t.label}
          {t.count != null && t.count > 0 && <span className="ml-1.5 text-xs tabular text-graphite">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

/** Sheet tabs along the bottom edge, like Model/Layout tabs in CAD. */
export function SheetTabs({ tabs, value, onChange, right }) {
  return (
    <div className="@container flex items-stretch border-t border-rule2 bg-plate">
      <div role="tablist" aria-label="Sheets" className="flex min-w-0 flex-1 overflow-x-auto">
        {tabs.map((t, i) => (
          <button
            key={t.id}
            role="tab"
            aria-selected={value === t.id}
            onClick={() => onChange(t.id)}
            title={t.hint}
            className={`relative shrink-0 border-r border-rule px-3.5 py-2 text-[0.8125rem] ${value === t.id ? "bg-sheet font-bold text-ink" : "text-pencil hover:bg-plate2 hover:text-ink"}`}
          >
            {value === t.id && <span className="absolute inset-x-0 top-[-1px] h-0.5 bg-ink" aria-hidden />}
            {t.label}
            {t.badge != null && t.badge > 0 && <span className="ml-1.5 text-xs tabular text-graphite">{t.badge}</span>}
            <span className="sr-only"> (key {i + 1})</span>
          </button>
        ))}
      </div>
      {right}
    </div>
  );
}

/* ---------- structure ---------- */
export function Section({ title, action, children, className = "" }) {
  return (
    <section className={`px-4 py-3 ${className}`}>
      <div className="mb-2 flex items-center gap-3">
        <h3 className="text-[0.8125rem] font-bold">{title}</h3>
        <span className="h-px flex-1 bg-rule" aria-hidden />
        {action}
      </div>
      {children}
    </section>
  );
}

/** Label/value rows with dotted leaders. */
export function Spec({ rows }) {
  return (
    <dl className="text-[0.8125rem]">
      {rows
        .filter(Boolean)
        .map(([k, v, opt]) => (
          <div key={k} className="flex items-baseline gap-2 py-[3px]">
            <dt className="shrink-0 text-pencil">{k}</dt>
            <span className="min-w-3 flex-1 translate-y-[-3px] border-b border-dotted border-rule2" aria-hidden />
            <dd className={`min-w-0 max-w-[75%] text-right ${opt?.mono ? "break-all font-mono text-xs" : "break-words"}`} title={opt?.title}>
              {v}
            </dd>
          </div>
        ))}
    </dl>
  );
}

/* ---------- overlays ---------- */
export function useOutside(ref, on, close) {
  useEffect(() => {
    if (!on) return undefined;
    const away = (e) => ref.current && !ref.current.contains(e.target) && close();
    const esc = (e) => e.key === "Escape" && (e.stopPropagation(), close());
    document.addEventListener("mousedown", away);
    document.addEventListener("keydown", esc, true);
    return () => {
      document.removeEventListener("mousedown", away);
      document.removeEventListener("keydown", esc, true);
    };
  }, [on, close, ref]);
}

export function Popover({ label, children, align = "right", variant = "default", width = "w-72", buttonClass = "" }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const panel = useRef(null);
  const close = () => setOpen(false);
  useOutside(ref, open, close);
  // keep the panel on screen on narrow viewports (`translate`, because the pop-in animation owns `transform`)
  useLayoutEffect(() => {
    const el = panel.current;
    if (!open || !el) return;
    el.style.translate = "";
    const r = el.getBoundingClientRect();
    const m = 8;
    const dx = r.left < m ? m - r.left : r.right > window.innerWidth - m ? window.innerWidth - m - r.right : 0;
    if (dx) el.style.translate = `${Math.round(dx)}px 0`;
  }, [open]);
  return (
    <div className="relative" ref={ref}>
      <Button variant={variant} onClick={() => setOpen((o) => !o)} aria-expanded={open} aria-haspopup="dialog" className={buttonClass}>
        {label}
      </Button>
      {open && (
        <div ref={panel} role="dialog" aria-label={typeof label === "string" ? label : undefined} className={`pop-in absolute z-40 mt-1.5 max-w-[calc(100vw-1rem)] ${width} ${align === "right" ? "right-0" : "left-0"} border border-rule2 bg-plate p-3 shadow-[0_8px_0_-4px_rgb(0_0_0/0.25)]`}>
          {typeof children === "function" ? children(close) : children}
        </div>
      )}
    </div>
  );
}

/** Native <dialog>, so focus trap, Esc and the inert background come from the browser. */
export function Dialog({ open, onClose, title, children, wide = false, top = false, drawer = false, label }) {
  const ref = useRef(null);
  const restore = useRef(null);
  useEffect(() => {
    const d = ref.current;
    if (!d) return undefined;
    if (open && !d.open) {
      restore.current = document.activeElement;
      try {
        d.showModal();
      } catch {
        d.setAttribute("open", "");
      }
    }
    if (!open && d.open) d.close();
    return () => {
      if (d.open) d.close();
    };
  }, [open]);
  useEffect(() => {
    if (!open) restore.current?.focus?.();
  }, [open]);
  if (!open) return <dialog ref={ref} className="hidden" />;
  const pos = drawer ? "m-0 ml-auto h-full max-h-none w-[min(26rem,100vw)] drawer-in" : top ? "mx-auto mt-[10vh] mb-auto" : "m-auto";
  return (
    <dialog
      ref={ref}
      aria-label={label || title}
      onClose={onClose}
      onClick={(e) => e.target === ref.current && onClose()}
      className={`${pos} ${!drawer ? (wide ? "w-[min(46rem,94vw)]" : "w-[min(30rem,94vw)]") : ""} max-h-[86vh] overflow-hidden border border-rule2 bg-plate p-0 text-ink shadow-[0_14px_0_-6px_rgb(0_0_0/0.3)]`}
    >
      <div className="flex max-h-[inherit] min-h-0 flex-col" style={{ maxHeight: drawer ? "100vh" : "86vh" }}>
        {title && (
          <div className="flex items-center gap-3 border-b border-rule px-4 py-2.5">
            <h2 className="flex-1 text-[0.9375rem] font-bold">{title}</h2>
            <Button variant="ghost" size="sm" onClick={onClose} aria-label="Close">
              Close
            </Button>
          </div>
        )}
        <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
      </div>
    </dialog>
  );
}

export function ConfirmDialog({ open, title, children, confirm = "Confirm", danger = false, busy = false, onConfirm, onClose }) {
  return (
    <Dialog open={open} onClose={onClose} title={title}>
      <div className="space-y-4 p-4">
        <div className="text-[0.8125rem] text-pencil">{children}</div>
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant={danger ? "danger" : "primary"} onClick={onConfirm} disabled={busy}>
            {busy && <Spinner />} {confirm}
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
