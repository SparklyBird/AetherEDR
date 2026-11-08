import { useState } from "react";
import { setKey } from "../lib/api";
import { DEFAULTS, THEME_LABELS, resetSettings, setSetting, useSettings } from "../lib/settings";
import { toast } from "../lib/toast";
import { Button, ConfirmDialog, Dialog, Kbd, Section, Segmented, Select, Switch } from "./ui";

const SWATCH = {
  cyanotype: { sheet: "#0b2338", plate: "#0e2c46", ink: "#e9f3f8", rule: "#3b7396", pen: "#ff6552", note: "Blueprint. Default." },
  graphite: { sheet: "#131517", plate: "#1a1d20", ink: "#eceff1", rule: "#4d555c", pen: "#ff6552", note: "Neutral dark." },
  vellum: { sheet: "#eef2f4", plate: "#e3e9ed", ink: "#0d2336", rule: "#8196a4", pen: "#bf2a1a", note: "Light, for print and daylight." },
};

const SHORTCUTS = [
  ["Ctrl K", "Search and commands"],
  ["1 to 6", "Switch sheet"],
  ["j  k", "Next, previous incident"],
  ["a", "Acknowledge selected incident"],
  ["x", "Mark selected incident false positive"],
  ["f", "Fit the lineage to the window"],
  ["+  −", "Zoom the lineage"],
  ["Arrows", "Walk the lineage from the selected process"],
  ["c", "Fold or unfold selected process"],
  ["/", "Find a process in the lineage"],
  ["t", "Cycle theme"],
  ["l", "Hide or show the incident log"],
  ["Esc", "Close dossier or dialog"],
];

function Row({ label, children }) {
  return (
    <div className="flex items-center justify-between gap-3 py-1.5 text-[0.8125rem]">
      <span>{label}</span>
      {children}
    </div>
  );
}

export default function SettingsDrawer({ open, onClose }) {
  const s = useSettings();
  const [confirm, setConfirm] = useState(false);
  const canNotify = typeof Notification !== "undefined";

  async function setNotify(on) {
    if (!on) return setSetting("notify", false);
    try {
      const p = Notification.permission === "granted" ? "granted" : await Notification.requestPermission();
      if (p === "granted") setSetting("notify", true);
      else toast({ title: "Notifications are blocked", body: "Allow them for this site in the browser's address bar, then try again.", tone: "bad", ms: 6000 });
    } catch {
      toast({ title: "This browser cannot show notifications", tone: "bad" });
    }
  }

  return (
    <>
      <Dialog open={open} onClose={onClose} title="Settings" drawer>
        <div className="divide-y divide-rule">
          <Section title="Sheet">
            <div role="radiogroup" aria-label="Theme" className="grid grid-cols-3 gap-2">
              {Object.entries(SWATCH).map(([k, c]) => (
                <button
                  key={k}
                  type="button"
                  role="radio"
                  aria-checked={s.theme === k}
                  onClick={() => setSetting("theme", k)}
                  className={`border p-1.5 text-left ${s.theme === k ? "border-ink" : "border-rule hover:border-rule2"}`}
                >
                  <svg viewBox="0 0 80 46" className="block w-full" aria-hidden>
                    <rect width="80" height="46" fill={c.sheet} />
                    <rect y="0" width="80" height="7" fill={c.plate} />
                    <path d="M8 24H20V16H34M20 24V34H34" stroke={c.rule} strokeWidth="1.4" fill="none" />
                    <circle cx="8" cy="24" r="2.4" fill={c.ink} />
                    <circle cx="34" cy="16" r="2.4" fill={c.ink} />
                    <circle cx="34" cy="34" r="2.6" fill={c.pen} />
                    <path d="M34 28a7 7 0 1 1-.1 0" stroke={c.pen} strokeWidth="1.2" fill="none" />
                    <path d="M44 34H70" stroke={c.rule} strokeWidth="1.4" />
                  </svg>
                  <span className="mt-1 block text-xs font-bold">{THEME_LABELS[k]}</span>
                  <span className="block text-[0.68rem] leading-tight text-graphite">{c.note}</span>
                </button>
              ))}
            </div>
            <Row label="Density">
              <Segmented size="sm" label="Density" value={s.density} onChange={(v) => setSetting("density", v)} options={[{ value: "comfortable", label: "Comfortable" }, { value: "compact", label: "Compact" }]} />
            </Row>
            <Row label="Text size">
              <Segmented size="sm" label="Text size" value={s.size} onChange={(v) => setSetting("size", v)} options={[{ value: "small", label: "Small" }, { value: "medium", label: "Medium" }, { value: "large", label: "Large" }]} />
            </Row>
            <Row label="Animation">
              <Segmented size="sm" label="Animation" value={s.motion} onChange={(v) => setSetting("motion", v)} options={[{ value: "system", label: "Follow system" }, { value: "off", label: "Off" }]} />
            </Row>
          </Section>

          <Section title="Lineage drawing">
            <Row label="Lines">
              <Segmented size="sm" label="Line style" value={s.edgeStyle} onChange={(v) => setSetting("edgeStyle", v)} options={[{ value: "elbow", label: "Elbow" }, { value: "curve", label: "Curve" }]} />
            </Row>
            <Row label="Labels">
              <Segmented size="sm" label="Labels" value={s.labels} onChange={(v) => setSetting("labels", v)} options={[{ value: "always", label: "Every process" }, { value: "selected", label: "Flagged only" }]} />
            </Row>
            <Row label="Hide below risk">
              <Select value={s.minRisk} onChange={(e) => setSetting("minRisk", +e.target.value)} className="!py-0.5 text-xs" aria-label="Minimum risk to draw">
                {[0, 10, 20, 40, 60, 80].map((v) => <option key={v} value={v}>{v === 0 ? "Show all" : `${v} and above`}</option>)}
              </Select>
            </Row>
            <Switch checked={s.groupSiblings} onChange={(v) => setSetting("groupSiblings", v)} label="Stack identical helpers" hint="Browsers start dozens of the same helper. Show them as one block." />
            <Switch checked={s.showNotes} onChange={(v) => setSetting("showNotes", v)} label="Reviewer's notes" hint="The top finding, in italic, under flagged processes" />
            <Switch checked={s.showExited} onChange={(v) => setSetting("showExited", v)} label="Include exited processes" />
          </Section>

          <Section title="Data">
            <Row label="Refresh lists every">
              <Select value={s.refresh} onChange={(e) => setSetting("refresh", +e.target.value)} className="!py-0.5 text-xs" aria-label="Refresh interval">
                <option value={5}>5 seconds</option>
                <option value={10}>10 seconds</option>
                <option value={30}>30 seconds</option>
                <option value={60}>1 minute</option>
                <option value={0}>Only when I ask</option>
              </Select>
            </Row>
            <p className="text-xs text-graphite">New alerts always arrive live. This only paces tables, the tree and the dossier.</p>
          </Section>

          <Section title="Attention">
            {canNotify && <Switch checked={s.notify} onChange={setNotify} label="Desktop notifications" hint="For new high and critical alerts, while this tab is in the background" />}
            <Switch checked={s.titleBadge} onChange={(v) => setSetting("titleBadge", v)} label="Open alert count in the tab title" />
          </Section>

          <Section title="Keyboard">
            <dl className="grid grid-cols-[auto_1fr] items-center gap-x-4 gap-y-1.5 text-[0.8125rem]">
              {SHORTCUTS.map(([k, d]) => (
                <div key={k} className="contents">
                  <dt><Kbd>{k}</Kbd></dt>
                  <dd className="text-pencil">{d}</dd>
                </div>
              ))}
            </dl>
          </Section>

          <Section title="Console">
            <div className="flex flex-wrap gap-2">
              <Button size="sm" onClick={() => setConfirm(true)}>Restore default settings</Button>
              <Button size="sm" onClick={() => (setKey(""), window.dispatchEvent(new Event("aether:unauthorized")))}>Use a different API key</Button>
            </div>
          </Section>
        </div>
      </Dialog>
      <ConfirmDialog open={confirm} title="Restore default settings?" confirm="Restore" onConfirm={() => (resetSettings(), setConfirm(false), toast({ title: "Settings restored", tone: "good", ms: 2500 }))} onClose={() => setConfirm(false)}>
        Theme, density, drawing and refresh options go back to their defaults ({THEME_LABELS[DEFAULTS.theme]} theme). Exceptions and alerts are not touched.
      </ConfirmDialog>
    </>
  );
}
