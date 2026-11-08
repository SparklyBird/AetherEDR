import { useSyncExternalStore } from "react";
import { load, save } from "./safe";

const KEY = "aether.settings.v2";

export const DEFAULTS = {
  theme: "cyanotype", // cyanotype | graphite | vellum
  density: "comfortable", // comfortable | compact
  size: "medium", // small | medium | large
  motion: "system", // system | off
  edgeStyle: "elbow", // elbow | curve
  labels: "always", // always | selected
  groupSiblings: true,
  showExited: false,
  showNotes: true,
  minRisk: 0,
  refresh: 10, // seconds between list refreshes; 0 = manual
  notify: false, // desktop notifications for high and critical alerts
  titleBadge: true,
};

const THEMES = ["cyanotype", "graphite", "vellum"];
let state = { ...DEFAULTS, ...pick(load(KEY, {})) };
const subs = new Set();

function pick(raw) {
  const out = {};
  if (!raw || typeof raw !== "object") return out;
  for (const k of Object.keys(DEFAULTS)) if (k in raw && typeof raw[k] === typeof DEFAULTS[k]) out[k] = raw[k];
  if (out.theme && !THEMES.includes(out.theme)) delete out.theme;
  return out;
}

export function applySettings(s = state) {
  const r = document.documentElement;
  r.dataset.theme = s.theme;
  r.dataset.density = s.density;
  r.dataset.size = s.size;
  r.dataset.motion = s.motion;
}

export function getSettings() {
  return state;
}

export function setSetting(key, value) {
  if (!(key in DEFAULTS)) return;
  state = { ...state, [key]: value };
  save(KEY, state);
  applySettings();
  subs.forEach((f) => f());
}

export function resetSettings() {
  state = { ...DEFAULTS };
  save(KEY, state);
  applySettings();
  subs.forEach((f) => f());
}

export function cycleTheme() {
  setSetting("theme", THEMES[(THEMES.indexOf(state.theme) + 1) % THEMES.length]);
}

export function useSettings() {
  return useSyncExternalStore(
    (f) => (subs.add(f), () => subs.delete(f)),
    () => state,
  );
}

export const THEME_LABELS = { cyanotype: "Cyanotype", graphite: "Graphite", vellum: "Vellum" };
