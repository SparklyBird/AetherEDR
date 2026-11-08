import { dismiss, useToasts } from "../lib/toast";

const TONE = { info: "var(--chalk)", good: "var(--ok)", bad: "var(--redline)", warn: "var(--marker)" };

export default function Toasts() {
  const items = useToasts();
  return (
    <div aria-live="polite" className="pointer-events-none fixed bottom-12 right-3 z-[60] flex w-[min(24rem,calc(100vw-1.5rem))] flex-col gap-2">
      {items.map((t) => (
        <div key={t.id} role={t.tone === "bad" ? "alert" : "status"} className="pop-in pointer-events-auto flex items-start gap-3 border border-rule2 bg-plate px-3 py-2.5 shadow-[0_6px_0_-3px_rgb(0_0_0/0.3)]" style={{ borderLeft: `3px solid ${TONE[t.tone] || TONE.info}` }}>
          <div className="min-w-0 flex-1">
            <p className="font-bold">{t.title}</p>
            {t.body && <p className="break-words text-[0.8125rem] text-pencil">{t.body}</p>}
            {t.action && (
              <button onClick={() => (t.action.run(), dismiss(t.id))} className="mt-1 text-[0.8125rem] font-bold underline underline-offset-2">
                {t.action.label}
              </button>
            )}
          </div>
          <button onClick={() => dismiss(t.id)} aria-label="Dismiss" className="text-pencil hover:text-ink">
            Close
          </button>
        </div>
      ))}
    </div>
  );
}
