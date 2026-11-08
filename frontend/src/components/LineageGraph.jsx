import { useCallback, useEffect, useId, useLayoutEffect, useMemo, useRef, useState } from "react";
import { api } from "../lib/api";
import { cloudPath } from "../lib/cloud";
import { colorForScore, midEllipsis, plural } from "../lib/format";
import { isTyping, useDebounced, useKeys, usePolled } from "../lib/hooks";
import { buildTree, collapsibleIds, isFlagged, isLineageHit } from "../lib/layout";
import { arr, load, save, saveBlob } from "../lib/safe";
import { setSetting, useSettings } from "../lib/settings";
import { toast } from "../lib/toast";
import KeysCard, { KEYS_CARD_HEIGHT, KEYS_CARD_SPACE, KEYS_MIN_PANE } from "./KeysCard";
import { Button, Empty, ErrorPanel, Input, Popover, Segmented, Select, Spinner, Switch } from "./ui";

const DX = 250;
const MIN_K = 0.08;
const MAX_K = 3;
const clampK = (k) => Math.min(MAX_K, Math.max(MIN_K, k));
const HALO = { paintOrder: "stroke", stroke: "var(--sheet)", strokeWidth: 5, strokeLinejoin: "round" };

function edgePath(a, b, style) {
  const x0 = a.x + 6;
  const x1 = b.x - 8;
  if (style === "curve") {
    const mx = (x0 + x1) / 2;
    return `M${x0},${a.y} C${mx},${a.y} ${mx},${b.y} ${x1},${b.y}`;
  }
  const mx = x0 + 18;
  return `M${x0},${a.y} H${mx} V${b.y} H${x1}`;
}

const trunc = (s, n) => (s && s.length > n ? `${s.slice(0, n - 1)}…` : s || "");

export default function LineageGraph({ host, selectedId, onSelect, focusId, onFocus, rev = 0 }) {
  const s = useSettings();
  const [scope, setScope] = useState("flagged");
  const [autoAll, setAutoAll] = useState(false);
  const [collapsed, setCollapsed] = useState(() => new Set());
  const [expanded, setExpanded] = useState(() => new Set());
  const [find, setFind] = useState("");
  const [findIdx, setFindIdx] = useState(0);
  const [view, setView] = useState({ x: 40, y: 60, k: 1 });
  const [size, setSize] = useState({ w: 800, h: 500 });
  const [hover, setHover] = useState(null);
  const [keysOpen, setKeysOpen] = useState(() => load("aether.keys.open", true) !== false);
  const roomForKeys = size.w >= KEYS_MIN_PANE; // in a narrow pane (the dossier is open, say) the card would only crowd the graph
  const keysShown = keysOpen && roomForKeys;
  const setKeys = (open) => {
    setKeysOpen(open);
    save("aether.keys.open", open);
  };

  const wrap = useRef(null);
  const topRef = useRef(null);
  const [topH, setTopH] = useState(76);
  const svgRef = useRef(null);
  const findRef = useRef(null);
  const drag = useRef(null);
  const pointers = useRef(new Map());
  const pinch = useRef(null);
  const fitted = useRef("");
  const moved = useRef(false); // set once the user pans or zooms, stops auto-framing
  const prevLayout = useRef(null);
  const gid = useId().replace(/:/g, "");

  const all = scope === "all" || autoAll;
  const dy = s.density === "compact" ? 30 : 40;

  const { data, error, loading, stale, reload } = usePolled(
    (signal) => api("graph/", { params: { host, focus: focusId ?? undefined, all: all ? 1 : undefined, alive: s.showExited ? 0 : 1, limit: 500 }, signal }),
    [host, focusId, all, s.showExited, rev],
    { interval: s.refresh },
  );

  useEffect(() => setAutoAll(false), [host, scope]);
  useEffect(() => {
    if (data && data.count === 0 && scope === "flagged" && !autoAll && focusId == null) setAutoAll(true);
  }, [data, scope, autoAll, focusId]);
  // The first poll can come back empty, on a fresh start before anything is scored. Once a later poll shows flagged
  // processes, return to the flagged view. An exited parent that still has a score is only drawn as an ancestor
  // (the server does not seed from it unless exited processes are shown), so it does not count here.
  useEffect(() => {
    if (!autoAll || scope !== "flagged" || focusId != null || !data) return;
    if (arr(data.nodes).some((n) => n.risk > 0 && (n.alive || s.showExited))) setAutoAll(false);
  }, [data, autoAll, scope, focusId, s.showExited]);

  const rawNodes = useMemo(() => arr(data?.nodes), [data]);
  const layout = useMemo(
    () => buildTree(rawNodes, { dx: DX, dy, minRisk: s.minRisk, focusId, collapsed, expanded, groupSiblings: s.groupSiblings }),
    [rawNodes, dy, s.minRisk, focusId, collapsed, expanded, s.groupSiblings],
  );
  const empty = !!data && !layout.nodes.length;
  // the tree plus breathing room: node halos, the label and note line under a node, and some air at the ends.
  // Framing and the minimap use this, so nothing sits right on the edge of the view
  const frame = useMemo(() => {
    const b = layout.bbox;
    return { x0: b.x0 - 32, y0: b.y0 - 48, x1: b.x1 + 32, y1: b.y1 + 64 };
  }, [layout]);

  /* ---- viewport size ---- */
  useEffect(() => {
    const el = wrap.current;
    if (!el) return undefined;
    const measure = () => setSize({ w: el.clientWidth || 800, h: el.clientHeight || 500 });
    measure();
    if (typeof ResizeObserver === "undefined") return undefined;
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  useEffect(() => {
    const el = topRef.current;
    if (!el || typeof ResizeObserver === "undefined") return undefined;
    const ro = new ResizeObserver(() => setTopH(Math.round(el.getBoundingClientRect().height)));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  /* ---- camera ---- */
  const keysTop = topH + (autoAll && scope === "flagged" && layout.nodes.length > 0 ? 34 : 12);
  const fit = useCallback(() => {
    const el = wrap.current;
    if (!el || !layout.nodes.length) return;
    const { x0, y0, x1, y1 } = frame;
    const w = el.clientWidth;
    const h = el.clientHeight;
    const padR = 24;
    const padTop = topH + 28; // clear of the toolbar and ruler
    const padBot = layout.nodes.length > 8 ? 132 : 24; // the minimap sits bottom right
    const place = (padL) => {
      const kFit = Math.min(1.25, (w - padL - padR) / Math.max(1, x1 - x0), (h - padTop - padBot) / Math.max(1, y1 - y0));
      const k = clampK(kFit);
      const spare = w - padL - padR - (x1 - x0) * k;
      return { k, x: padL - x0 * k + Math.max(0, spare) / 2, y: padTop - y0 * k + Math.max(0, h - padTop - padBot - (y1 - y0) * k) / 2 };
    };
    let v = place(24);
    if (keysOpen && w >= KEYS_MIN_PANE && window.innerWidth >= 768) {
      // the keys card sits top left: keep that strip clear only when the graph would actually run into it
      const hits = layout.nodes.some((n) => {
        const sx = v.x + n.x * v.k;
        const sy = v.y + n.y * v.k;
        return sx < KEYS_CARD_SPACE && sy > keysTop - 16 && sy < keysTop + KEYS_CARD_HEIGHT + 16;
      });
      if (hits) v = place(KEYS_CARD_SPACE);
    }
    setView(v);
  }, [layout, frame, topH, keysOpen, keysTop]);

  // opening or closing the keys card re-frames, unless the user has already moved the view
  const keysSeen = useRef(keysShown);
  useLayoutEffect(() => {
    if (keysSeen.current === keysShown) return;
    keysSeen.current = keysShown;
    if (!moved.current) fit();
  }, [keysShown, fit]);

  // auto-frame only until the user pans or zooms (or host/scope/focus changes). After that a refresh
  // keeps what they are looking at in the same screen position, even if the layout shifts
  useLayoutEffect(() => {
    if (!layout.nodes.length) {
      prevLayout.current = layout;
      return;
    }
    const el = wrap.current;
    const sig = `${host}|${all}|${focusId}|${s.minRisk}`;
    const prev = prevLayout.current;
    prevLayout.current = layout;
    if (fitted.current !== sig) {
      fitted.current = sig;
      moved.current = false;
      fit();
      return;
    }
    if (!moved.current) {
      if (!prev || prev.nodes.length !== layout.nodes.length) fit();
      return;
    }
    if (!prev || !prev.nodes.length || !el) return;
    const cx = el.clientWidth / 2;
    const cy = el.clientHeight / 2;
    setView((v) => {
      const wx = (cx - v.x) / v.k;
      const wy = (cy - v.y) / v.k;
      let anchor = null;
      let best = Infinity;
      for (const n of prev.nodes) {
        const d = (n.x - wx) ** 2 + (n.y - wy) ** 2;
        if (d < best) (best = d), (anchor = n);
      }
      const now = anchor && layout.byId.get(anchor.id);
      if (!now) return v;
      const ddx = (anchor.x - now.x) * v.k;
      const ddy = (anchor.y - now.y) * v.k;
      return ddx || ddy ? { ...v, x: v.x + ddx, y: v.y + ddy } : v;
    });
  }, [layout, fit, host, all, focusId, s.minRisk]);

  useEffect(() => {
    if (!moved.current && layout.nodes.length) fit();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [size.w, size.h, topH]);

  const refit = () => {
    moved.current = false;
    fit();
  };

  const zoomAt = useCallback((f, px, py) => {
    moved.current = true;
    setView((v) => {
      const k = clampK(v.k * f);
      return { k, x: px - ((px - v.x) / v.k) * k, y: py - ((py - v.y) / v.k) * k };
    });
  }, []);

  useEffect(() => {
    const el = wrap.current;
    if (!el) return undefined;
    const onWheel = (e) => {
      e.preventDefault();
      const r = el.getBoundingClientRect();
      zoomAt(Math.exp(-e.deltaY * 0.0015), e.clientX - r.left, e.clientY - r.top);
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, [zoomAt]);

  // The toolbar and ruler sit on top of the canvas, so the visible part starts at topH.
  // Centering, zoom and the minimap box all use that part, not the full element.
  const visH = Math.max(1, size.h - topH);
  const visMidY = topH + visH / 2;
  const zoomBy = (f) => zoomAt(f, size.w / 2, visMidY);

  const centerOn = useCallback(
    (n, onlyIfOutside = false) => {
      if (!n) return;
      setView((v) => {
        const sx = v.x + n.x * v.k;
        const sy = v.y + n.y * v.k;
        if (onlyIfOutside && sx > 60 && sx < size.w - 200 && sy > topH + 24 && sy < size.h - 50) return v;
        return { ...v, x: size.w / 2 - 80 - n.x * v.k, y: visMidY - n.y * v.k };
      });
      moved.current = true;
    },
    [size.w, size.h, topH, visMidY],
  );

  // scroll to a node when something outside the graph selects it
  useEffect(() => {
    if (selectedId != null) centerOn(layout.byId.get(selectedId), true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedId]);

  /* ---- find ---- */
  const q = useDebounced(find, 150).trim().toLowerCase();
  const matches = useMemo(
    () => (q ? layout.nodes.filter((n) => !n.group && `${n.name} ${n.pid} ${n.cmdline || ""} ${n.user || ""}`.toLowerCase().includes(q)) : []),
    [layout, q],
  );
  const matchIds = useMemo(() => new Set(matches.map((m) => m.id)), [matches]);
  useEffect(() => setFindIdx(0), [q]);
  const nextMatch = () => {
    if (!matches.length) return;
    const n = matches[findIdx % matches.length];
    setFindIdx((i) => i + 1);
    onSelect(n.id);
    centerOn(n);
  };

  /* ---- fold ---- */
  const toggleFold = (n) => {
    if (!n.hasKids) return;
    setCollapsed((c) => {
      const x = new Set(c);
      x.has(n.id) ? x.delete(n.id) : x.add(n.id);
      return x;
    });
  };
  const foldAll = () => setCollapsed(new Set(collapsibleIds(rawNodes)));
  const unfoldAll = () => (setCollapsed(new Set()), setExpanded(new Set(layout.nodes.filter((n) => n.group).map((n) => n.id))));

  /* ---- keyboard ---- */
  const nav = (e) => {
    const cur = layout.byId.get(selectedId);
    if (!cur || e.altKey || e.ctrlKey || e.metaKey) return;
    let next = null;
    if (e.key === "ArrowLeft") next = layout.byId.get(cur.parent);
    else if (e.key === "ArrowRight") next = layout.nodes.filter((n) => n.parent === cur.id).sort((a, b) => a.y - b.y)[0];
    else if (e.key === "ArrowUp" || e.key === "ArrowDown") {
      const col = layout.nodes.filter((n) => n.depth === cur.depth).sort((a, b) => a.y - b.y);
      const i = col.findIndex((n) => n.id === cur.id);
      next = col[i + (e.key === "ArrowDown" ? 1 : -1)];
    }
    if (next && !next.group) {
      e.preventDefault();
      onSelect(next.id);
      centerOn(next, true);
    }
  };
  useKeys((e) => {
    if (isTyping(e) || e.ctrlKey || e.metaKey || e.altKey || document.querySelector("dialog[open]")) return;
    if (e.key === "f") (refit(), e.preventDefault());
    else if (e.key === "+" || e.key === "=") (zoomBy(1.25), e.preventDefault());
    else if (e.key === "-") (zoomBy(1 / 1.25), e.preventDefault());
    else if (e.key === "c" && selectedId != null) toggleFold(layout.byId.get(selectedId) || {});
    else if (e.key === "/") (findRef.current?.focus(), e.preventDefault());
  });

  /* ---- pointer: pan with one finger, pinch with two ---- */
  const onPointerDown = (e) => {
    if (e.target.closest("[data-node],[data-ui]")) return;
    moved.current = true;
    pointers.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
    try {
      e.currentTarget.setPointerCapture(e.pointerId);
    } catch {
      /* synthetic pointer ids can't be captured */
    }
    if (pointers.current.size === 1) drag.current = { x: e.clientX - view.x, y: e.clientY - view.y };
    else if (pointers.current.size === 2) {
      drag.current = null;
      const [a, b] = [...pointers.current.values()];
      const r = e.currentTarget.getBoundingClientRect();
      const mx = (a.x + b.x) / 2 - r.left;
      const my = (a.y + b.y) / 2 - r.top;
      pinch.current = { dist: Math.hypot(a.x - b.x, a.y - b.y) || 1, k: view.k, wx: (mx - view.x) / view.k, wy: (my - view.y) / view.k };
    }
  };
  const onPointerMove = (e) => {
    if (pointers.current.has(e.pointerId)) pointers.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
    const p = pinch.current;
    if (p && pointers.current.size === 2) {
      const [a, b] = [...pointers.current.values()];
      const r = e.currentTarget.getBoundingClientRect();
      const k = clampK((p.k * Math.hypot(a.x - b.x, a.y - b.y)) / p.dist);
      const mx = (a.x + b.x) / 2 - r.left;
      const my = (a.y + b.y) / 2 - r.top;
      setView({ k, x: mx - p.wx * k, y: my - p.wy * k });
      return;
    }
    const d = drag.current; // read now, React runs the updater later and pointerup may have cleared the ref
    if (!d) return;
    const x = e.clientX - d.x;
    const y = e.clientY - d.y;
    setView((v) => ({ ...v, x, y }));
  };
  const onPointerEnd = (e) => {
    pointers.current.delete(e.pointerId);
    pinch.current = null;
    drag.current = null;
    if (pointers.current.size === 1) {
      const [rest] = [...pointers.current.values()];
      drag.current = { x: rest.x - view.x, y: rest.y - view.y };
    }
  };

  /* ---- export ---- */
  function exportSvg() {
    try {
      const world = svgRef.current?.querySelector("[data-world]");
      if (!world || !layout.nodes.length) return;
      const g = world.cloneNode(true);
      g.removeAttribute("transform");
      const cs = getComputedStyle(document.documentElement);
      const sub = (str) => str.replace(/var\((--[a-z0-9-]+)\)/g, (_, v) => cs.getPropertyValue(v).trim() || "#888");
      const { x0, y0, x1, y1 } = layout.bbox;
      const pad = 36;
      const w = x1 - x0 + pad * 2;
      const h = y1 - y0 + pad * 2 + 26;
      const vx = x0 - pad;
      const vy = y0 - pad - 26;
      const title = `AetherEDR process lineage, ${new Date().toLocaleString()}${host ? "" : ", all hosts"}`;
      const out = sub(
        `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${vx} ${vy} ${w} ${h}" width="${Math.round(w)}" height="${Math.round(h)}" font-family="B612, Arial, sans-serif">` +
          `<rect x="${vx}" y="${vy}" width="${w}" height="${h}" fill="var(--sheet)"/>` +
          `<text x="${vx + 12}" y="${vy + 20}" font-size="12" fill="var(--pencil)">${title.replace(/&/g, "&amp;").replace(/</g, "&lt;")}</text>` +
          `${new XMLSerializer().serializeToString(g)}</svg>`,
      );
      saveBlob(new Blob([out], { type: "image/svg+xml" }), `AetherEDR-lineage-${new Date().toISOString().slice(0, 16).replace(/[:T-]/g, "")}.svg`);
      toast({ title: "Drawing saved", body: "Open the SVG in a browser or drawing tool.", tone: "good", ms: 3500 });
    } catch (e) {
      toast({ title: "Could not save the drawing", body: String(e?.message || e), tone: "bad" });
    }
  }

  /* ---- derived drawing data ---- */
  const hovered = hover != null ? layout.byId.get(hover) : null;
  const ordered = useMemo(() => {
    // draw order: quiet, flagged, selected
    const rank = (n) => (n.id === selectedId ? 2 : isFlagged(n) ? 1 : 0);
    return [...layout.nodes].sort((a, b) => rank(a) - rank(b));
  }, [layout, selectedId]);
  const columns = useMemo(() => Array.from({ length: layout.maxDepth + 1 }, (_, d) => d), [layout.maxDepth]);
  const minimap = useMemo(() => {
    const { x0, y0, x1, y1 } = frame;
    const W = 168;
    const H = 108;
    const pad = 14; // room between the drawing and the box edge, inside the box
    const sc = Math.min((W - pad * 2) / Math.max(1, x1 - x0), (H - pad * 2) / Math.max(1, y1 - y0));
    return { W, H, sc, x0, y0, offX: (W - (x1 - x0) * sc) / 2, offY: (H - (y1 - y0) * sc) / 2 };
  }, [frame]);

  const showLabel = (n) => s.labels === "always" || isFlagged(n) || n.id === selectedId || n.id === hover || matchIds.has(n.id) || n.group;
  const dim = q && !matches.length ? false : !!q;

  return (
    <section aria-label="Process lineage" className="sheet-canvas relative h-full min-h-0 overflow-hidden">
      <div
        ref={wrap}
        tabIndex={0}
        onKeyDown={nav}
        className="absolute inset-0 cursor-grab touch-none outline-none focus-visible:outline-offset-[-3px] active:cursor-grabbing"
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={onPointerEnd}
        onPointerCancel={onPointerEnd}
        onLostPointerCapture={onPointerEnd}
      >
        <svg ref={svgRef} width="100%" height="100%" role="group" aria-label={`Process tree with ${plural(layout.nodes.length, "process", "processes")}`}>
          <defs>
            <pattern id={`g${gid}`} width="50" height="50" patternUnits="userSpaceOnUse" patternTransform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
              <path d="M50 0H0V50" fill="none" stroke="var(--rule)" strokeWidth={0.8 / Math.max(0.5, view.k)} opacity="0.55" />
            </pattern>
          </defs>
          <rect width="100%" height="100%" fill={`url(#g${gid})`} />
          <g data-world transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
            {layout.nodes.length > 0 && columns.map((d) => (
              <line key={`col${d}`} x1={d * DX - 16} x2={d * DX - 16} y1={layout.bbox.y0 - 30} y2={layout.bbox.y1 + 30} stroke="var(--rule2)" strokeDasharray="1 6" opacity="0.7" />
            ))}
            {layout.edges.map(({ from, to }) => {
              const hot = isLineageHit(to);
              const warm = !hot && to.risk >= 60;
              return (
                <path
                  key={`${from.id}-${to.id}`}
                  d={edgePath(from, to, s.edgeStyle)}
                  fill="none"
                  stroke={hot ? "var(--redline)" : warm ? "var(--marker)" : "var(--rule2)"}
                  strokeWidth={hot ? 2.4 : warm ? 1.7 : 1.2}
                  opacity={hot || warm ? 1 : to.alive === false ? 0.45 : 0.9}
                  strokeDasharray={to.alive === false && !hot ? "3 3" : undefined}
                  className={hot ? "hot-edge" : ""}
                  style={hot ? { "--len": Math.hypot(to.x - from.x, to.y - from.y) * 1.5 } : undefined}
                />
              );
            })}
            {ordered.map((n) => {
              const flagged = !n.group && isFlagged(n);
              const sel = n.id === selectedId;
              const col = colorForScore(n.risk);
              const memory = !n.group && (n.rwx > 0 || n.unbacked > 0);
              const label = n.group ? `${n.name}  ×${n.count}` : n.name;
              const lx = n.group ? 16 : flagged ? 21 : 12;
              const faded = dim && !matchIds.has(n.id) && !sel;
              const w = Math.min(label.length, 28) * 7.2 + (n.group ? 0 : String(n.pid).length * 6.5 + 8);
              return (
                <g
                  key={n.id}
                  data-node
                  transform={`translate(${n.x} ${n.y})`}
                  tabIndex={0}
                  role="button"
                  aria-label={n.group ? `${n.count} ${n.name} processes grouped. Activate to show them.` : `${n.name}, PID ${n.pid}, risk ${n.risk}${n.top ? `, ${n.top}` : ""}${n.alive === false ? ", exited" : ""}`}
                  aria-pressed={n.group ? undefined : sel}
                  className="cursor-pointer outline-none [&:focus-visible>rect.focus]:stroke-chalk"
                  opacity={faded ? 0.25 : n.alive === false ? 0.55 : 1}
                  onClick={() => (n.group ? setExpanded((x) => new Set(x).add(n.id)) : onSelect(n.id))}
                  onDoubleClick={() => !n.group && toggleFold(n)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      e.preventDefault();
                      n.group ? setExpanded((x) => new Set(x).add(n.id)) : onSelect(n.id);
                    }
                  }}
                  onPointerEnter={() => setHover(n.id)}
                  onPointerLeave={() => setHover(null)}
                >
                  <rect className="focus" x="-12" y={-dy / 2 + 2} width={lx + w + 16} height={dy - 4} fill="transparent" stroke="transparent" strokeWidth="2" rx="2" />
                  {sel && <rect x="-11" y="-13" width={lx + w + 12} height={flagged && s.showNotes && n.top ? 38 : 26} fill="none" stroke="var(--ink)" strokeDasharray="4 3" />}
                  {flagged && <path d={cloudPath(0, 0, 15, n.id, 10)} fill="none" stroke={col} strokeWidth="1.7" />}
                  {n.group ? (
                    <g fill="var(--plate)" stroke="var(--pencil)" strokeWidth="1.2">
                      <rect x="-1" y="-8" width="11" height="11" />
                      <rect x="-4" y="-5" width="11" height="11" />
                      <rect x="-7" y="-2" width="11" height="11" />
                    </g>
                  ) : (
                    <>
                      {memory && <circle r="9" fill="none" stroke="var(--chalk)" strokeWidth="1.3" strokeDasharray="2.5 2.5" />}
                      <circle r={flagged ? 5.5 : 4.5} fill={n.alive === false ? "var(--sheet)" : flagged ? col : "var(--ink)"} stroke={flagged ? col : "var(--ink)"} strokeWidth="1.5" />
                    </>
                  )}
                  {showLabel(n) && (
                    <text x={lx} y={flagged && s.showNotes && n.top ? -2 : 4} fontSize="12.5" fontWeight={flagged || sel ? 700 : 400} fill={flagged ? col : "var(--ink)"} style={HALO} textDecoration={matchIds.has(n.id) ? "underline" : undefined}>
                      {trunc(label, 28)}
                      {!n.group && (
                        <tspan fill="var(--graphite)" fontWeight="400" dx="6" fontSize="10.5">
                          {n.pid}
                        </tspan>
                      )}
                      {n.collapsed && (
                        <tspan fill="var(--chalk)" fontWeight="400" dx="7" fontSize="11">
                          +{n.hidden}
                        </tspan>
                      )}
                    </text>
                  )}
                  {flagged && s.showNotes && n.top && showLabel(n) && (
                    <text x={lx} y="13" fontSize="11" fontStyle="italic" fill={col} style={HALO}>
                      {trunc(n.top, 38)}
                    </text>
                  )}
                </g>
              );
            })}
          </g>
        </svg>
      </div>

      {/* toolbar + generation ruler */}
      <div ref={topRef} data-ui className="pointer-events-none absolute inset-x-0 top-0 z-10">
      <div className="pointer-events-auto flex flex-wrap items-center gap-2 border-b border-rule bg-[color-mix(in_srgb,var(--sheet)_90%,transparent)] px-3 py-2">
        <Segmented
          size="sm"
          label="Which processes to draw"
          value={all ? "all" : "flagged"}
          onChange={(v) => (setScope(v), setAutoAll(false))}
          options={[
            { value: "flagged", label: "Flagged", title: "Processes with a risk score, plus the parents that launched them" },
            { value: "all", label: "All running" },
          ]}
        />
        <div className="relative">
          <Input
            ref={findRef}
            type="search"
            value={find}
            onChange={(e) => setFind(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && (e.preventDefault(), nextMatch())}
            placeholder="Find process  /"
            aria-label="Find a process in the tree"
            className="w-44 !py-1 text-xs"
          />
        </div>
        {q && (
          <button type="button" onClick={nextMatch} className="text-xs text-pencil underline underline-offset-2 hover:text-ink">
            {matches.length ? `${matches.length} found, next` : "none found"}
          </button>
        )}
        {focusId != null && (
          <Button size="sm" onClick={() => onFocus(null)} title="Show the whole tree again">
            Focused. Show all
          </Button>
        )}
        <span className="ml-auto flex flex-wrap items-center gap-1.5">
          {stale && <span className="text-xs text-marker" title={error?.message}>Showing last update</span>}
          {loading && <Spinner />}
          <Popover label="View" align="right" width="w-80" buttonClass="!px-2.5 !py-1 !text-xs">
            <div className="space-y-1">
              <label className="flex items-center justify-between gap-3 py-1 text-[0.8125rem]">
                Hide below risk
                <Select value={s.minRisk} onChange={(e) => setSetting("minRisk", +e.target.value)} className="!py-0.5 text-xs" aria-label="Minimum risk to draw">
                  {[0, 10, 20, 40, 60, 80].map((v) => (
                    <option key={v} value={v}>{v === 0 ? "Show all" : `${v} and above`}</option>
                  ))}
                </Select>
              </label>
              <Switch checked={s.groupSiblings} onChange={(v) => setSetting("groupSiblings", v)} label="Stack identical helpers" hint="Four or more quiet siblings with one name become a single block" />
              <Switch checked={s.showNotes} onChange={(v) => setSetting("showNotes", v)} label="Reviewer's notes" hint="Show the top finding under flagged processes" />
              <Switch checked={s.showExited} onChange={(v) => setSetting("showExited", v)} label="Include exited processes" />
              <div className="flex items-center justify-between gap-3 py-1 text-[0.8125rem]">
                Labels
                <Segmented size="sm" label="Labels" value={s.labels} onChange={(v) => setSetting("labels", v)} options={[{ value: "always", label: "All" }, { value: "selected", label: "Flagged" }]} />
              </div>
              <div className="flex items-center justify-between gap-3 py-1 text-[0.8125rem]">
                Lines
                <Segmented size="sm" label="Line style" value={s.edgeStyle} onChange={(v) => setSetting("edgeStyle", v)} options={[{ value: "elbow", label: "Elbow" }, { value: "curve", label: "Curve" }]} />
              </div>
              <div className="flex gap-2 pt-1">
                <Button size="sm" onClick={foldAll} className="flex-1">Fold all</Button>
                <Button size="sm" onClick={unfoldAll} className="flex-1">Unfold all</Button>
              </div>
            </div>
          </Popover>
          {selectedId != null && focusId == null && (
            <Button size="sm" onClick={() => onFocus(selectedId)} title="Draw only the selected process, its parents and its descendants">
              Focus
            </Button>
          )}
          <Button size="sm" onClick={() => zoomBy(1 / 1.25)} aria-label="Zoom out" className="!px-2.5">−</Button>
          <Button size="sm" onClick={() => zoomBy(1.25)} aria-label="Zoom in" className="!px-2.5">+</Button>
          <Button size="sm" onClick={refit} title="Frame everything (f)">Fit</Button>
          <Button size="sm" variant="ghost" onClick={exportSvg} disabled={!layout.nodes.length} title="Save this tree as an SVG drawing">Save SVG</Button>
          <Button size="sm" variant="ghost" onClick={reload} title="Refresh now">Refresh</Button>
        </span>
      </div>
          {/* generation ruler */}
          {layout.nodes.length > 0 && (
            <div className="pointer-events-none relative h-5 overflow-hidden border-b border-rule2 bg-[color-mix(in_srgb,var(--sheet)_88%,transparent)]" aria-hidden>
              {columns.map((d) => {
                const x = view.x + (d * DX - 16) * view.k;
                return x > -60 && x < size.w ? (
                  <span key={d} className="absolute top-0 flex h-full items-end border-l border-rule2 pl-1.5 pb-0.5 text-[0.68rem] leading-none text-graphite" style={{ left: x }}>
                    {d === 0 ? "roots" : `child ${d}`}
                  </span>
                ) : null;
              })}
            </div>
          )}
      </div>

      {/* states */}
      {!data && !error && (
        <div className="absolute inset-0 grid place-items-center">
          <Spinner />
        </div>
      )}
      {error && !data && (
        <div className="absolute inset-x-0 top-20 mx-auto max-w-md" data-ui>
          <ErrorPanel error={error} onRetry={reload} title="Could not load the process tree" />
        </div>
      )}
      {empty && (
        <div className="absolute inset-0 grid place-items-center" data-ui>
          <Empty title={s.minRisk ? "Everything is below the risk filter" : "No processes to draw yet"} action={s.minRisk ? <Button size="sm" onClick={() => setSetting("minRisk", 0)}>Show all</Button> : null}>
            {s.minRisk ? "Lower the risk filter in View." : "The collector reports its first processes within a few seconds."}
          </Empty>
        </div>
      )}
      {autoAll && scope === "flagged" && layout.nodes.length > 0 && (
        <p data-ui className="absolute left-3 text-xs text-pencil" style={{ top: topH + 6 }}>Nothing is flagged. Showing everything running.</p>
      )}

      {/* legend */}
      <details data-ui className="absolute bottom-3 left-3 hidden max-w-[17rem] border border-rule2 bg-[color-mix(in_srgb,var(--plate)_94%,transparent)] text-xs text-pencil md:block">
        <summary className="cursor-pointer px-2.5 py-1.5 text-ink">Legend</summary>
        <dl className="space-y-1.5 border-t border-rule px-2.5 py-2">
          <div className="flex items-center gap-2">
            <svg width="30" height="22" aria-hidden><path d={cloudPath(15, 11, 9, 4, 8)} fill="none" stroke="var(--redline)" strokeWidth="1.5" /><circle cx="15" cy="11" r="3.5" fill="var(--redline)" /></svg>
            <dd>Flagged, risk 40 or more</dd>
          </div>
          <div className="flex items-center gap-2">
            <svg width="30" height="14" aria-hidden><circle cx="15" cy="7" r="6" fill="none" stroke="var(--chalk)" strokeDasharray="2.5 2.5" /><circle cx="15" cy="7" r="3" fill="var(--ink)" /></svg>
            <dd>Suspicious executable memory</dd>
          </div>
          <div className="flex items-center gap-2">
            <svg width="30" height="8" aria-hidden><path d="M1 4h28" stroke="var(--redline)" strokeWidth="2.4" /></svg>
            <dd>Unexpected parent launched it</dd>
          </div>
          <div className="flex items-center gap-2">
            <svg width="30" height="14" aria-hidden><circle cx="15" cy="7" r="4" fill="var(--sheet)" stroke="var(--ink)" strokeWidth="1.5" opacity=".6" /></svg>
            <dd>Exited</dd>
          </div>
          <p className="pt-1 text-graphite">Double-click folds children. Arrow keys move along the tree.</p>
        </dl>
      </details>

      {roomForKeys && (
        <KeysCard open={keysOpen} onOpen={() => setKeys(true)} onClose={() => setKeys(false)} top={keysTop} />
      )}

      {/* minimap */}
      {layout.nodes.length > 8 && (
        <svg
          data-ui
          width={minimap.W}
          height={minimap.H}
          className="absolute bottom-3 right-3 hidden cursor-pointer border border-rule2 bg-[color-mix(in_srgb,var(--plate)_94%,transparent)] md:block"
          role="img"
          aria-label="Overview of the whole tree. Click to move the view."
          onPointerDown={(e) => {
            const r = e.currentTarget.getBoundingClientRect();
            const wx = (e.clientX - r.left - minimap.offX) / minimap.sc + minimap.x0;
            const wy = (e.clientY - r.top - minimap.offY) / minimap.sc + minimap.y0;
            moved.current = true;
            setView((v) => ({ ...v, x: size.w / 2 - wx * v.k, y: visMidY - wy * v.k }));
          }}
        >
          {layout.nodes.map((n) => (
            <rect key={n.id} x={minimap.offX + (n.x - minimap.x0) * minimap.sc} y={minimap.offY + (n.y - minimap.y0) * minimap.sc} width="2.5" height="2.5" fill={isFlagged(n) ? colorForScore(n.risk) : "var(--graphite)"} />
          ))}
          {(() => {
            // the view box is kept inside the minimap, a few pixels from its edge, even when the view is larger than the tree
            const inset = 4;
            const bx0 = minimap.offX + (-view.x / view.k - minimap.x0) * minimap.sc;
            const by0 = minimap.offY + ((topH - view.y) / view.k - minimap.y0) * minimap.sc;
            const bx1 = bx0 + (size.w / view.k) * minimap.sc;
            const by1 = by0 + (visH / view.k) * minimap.sc;
            const x = Math.max(inset, bx0);
            const y = Math.max(inset, by0);
            return (
              <rect
                x={x}
                y={y}
                width={Math.max(4, Math.min(minimap.W - inset, bx1) - x)}
                height={Math.max(4, Math.min(minimap.H - inset, by1) - y)}
                fill="none"
                stroke="var(--ink)"
                strokeWidth="1"
              />
            );
          })()}
        </svg>
      )}

      {hovered && !hovered.group && (hovered.cmdline || hovered.exe) && (
        <div className="pointer-events-none absolute bottom-3 left-1/2 max-w-[min(34rem,90vw)] -translate-x-1/2 border border-rule2 bg-plate px-3 py-2 text-xs shadow-[0_6px_0_-3px_rgb(0_0_0/0.3)]">
          <p className="font-bold">
            {hovered.name} <span className="font-normal text-pencil">PID {hovered.pid}, {hovered.host}, {hovered.user || "unknown user"}</span>
          </p>
          <p className="mt-1 break-all font-mono text-[0.7rem] text-pencil">{midEllipsis(hovered.cmdline || hovered.exe, 260)}</p>
        </div>
      )}
    </section>
  );
}
