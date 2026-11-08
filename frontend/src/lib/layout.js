// Turns the process forest into a positioned tree. Depth is the column, leaves get consecutive rows,
// parents sit in the middle of their children. Bad input gives an empty tree.
const FLAG_RISK = 40;
const GROUP_MIN = 4;

export const isLineageHit = (n) => (n.rules || []).some((r) => typeof r === "string" && r.startsWith("LIN-"));
export const isFlagged = (n) => (n.risk || 0) >= FLAG_RISK;

function indexNodes(nodes) {
  const byId = new Map();
  for (const n of Array.isArray(nodes) ? nodes : []) if (n && n.id != null) byId.set(n.id, n);
  return byId;
}

function ancestorsOf(id, byId) {
  const out = [];
  const seen = new Set([id]);
  let cur = byId.get(id);
  while (cur && cur.parent != null && byId.has(cur.parent) && !seen.has(cur.parent)) {
    out.push(cur.parent);
    seen.add(cur.parent);
    cur = byId.get(cur.parent);
  }
  return out;
}

export function buildTree(rawNodes, opts = {}) {
  const { dx = 250, dy = 40, minRisk = 0, focusId = null, collapsed = new Set(), expanded = new Set(), groupSiblings = true } = opts;
  const byId = indexNodes(rawNodes);

  // 1. filters: risk floor (keeping ancestors so the path stays readable) and focus mode
  let keep = new Set(byId.keys());
  if (minRisk > 0) {
    keep = new Set();
    for (const n of byId.values()) {
      if ((n.risk || 0) >= minRisk) {
        keep.add(n.id);
        ancestorsOf(n.id, byId).forEach((a) => keep.add(a));
      }
    }
  }
  if (focusId != null && byId.has(focusId)) {
    const family = new Set([focusId, ...ancestorsOf(focusId, byId)]);
    const kids = new Map();
    for (const n of byId.values()) if (n.parent != null) (kids.get(n.parent) || kids.set(n.parent, []).get(n.parent)).push(n.id);
    const stack = [focusId];
    while (stack.length) for (const k of kids.get(stack.pop()) || []) if (!family.has(k)) (family.add(k), stack.push(k));
    keep = new Set([...keep].filter((id) => family.has(id)));
    keep.add(focusId);
  }

  // 2. children map over kept nodes
  const kids = new Map();
  const roots = [];
  for (const id of keep) {
    const n = byId.get(id);
    if (n.parent != null && keep.has(n.parent) && n.parent !== id) (kids.get(n.parent) || kids.set(n.parent, []).get(n.parent)).push(n);
    else roots.push(n);
  }
  const descendants = (id) => {
    let c = 0;
    const st = [id];
    while (st.length) for (const k of kids.get(st.pop()) || []) (c++, st.push(k.id));
    return c;
  };

  // 3. place
  const order = (a, b) => (b.risk || 0) - (a.risk || 0) || (a.pid || 0) - (b.pid || 0);
  const placed = [];
  const edges = [];
  const seen = new Set();
  let row = 0;
  let maxDepth = 0;

  function place(n, depth, parent) {
    if (seen.has(n.id)) return null;
    seen.add(n.id);
    maxDepth = Math.max(maxDepth, depth);
    const node = { ...n, depth, x: depth * dx, y: 0, hidden: 0, hasKids: false, group: false };
    placed.push(node);
    let children = (kids.get(n.id) || []).slice().sort(order);
    node.hasKids = children.length > 0;
    if (collapsed.has(n.id) && children.length) {
      node.hidden = descendants(n.id);
      node.collapsed = true;
      children = [];
    }

    // identical quiet leaf siblings collapse into one stack (forty chrome.exe helpers, one node)
    const units = [];
    if (groupSiblings && children.length >= GROUP_MIN) {
      const byName = new Map();
      for (const c of children) {
        const isLeaf = !(kids.get(c.id) || []).length;
        if (isLeaf && !isFlagged(c) && c.id !== focusId) (byName.get(c.name) || byName.set(c.name, []).get(c.name)).push(c);
      }
      const grouped = new Set();
      for (const [name, list] of byName) {
        const gid = `g:${n.id}:${name}`;
        if (list.length >= GROUP_MIN && !expanded.has(gid)) {
          list.forEach((m) => grouped.add(m.id));
          units.push({ group: true, id: gid, name, members: list, parent: n.id, risk: Math.max(...list.map((m) => m.risk || 0)), alive: list.some((m) => m.alive) });
        }
      }
      for (const c of children) if (!grouped.has(c.id)) units.push(c);
      units.sort((a, b) => order(a, b) || String(a.name).localeCompare(String(b.name)));
    } else units.push(...children);

    const placedKids = [];
    for (const u of units) {
      if (u.group) {
        if (seen.has(u.id)) continue;
        seen.add(u.id);
        const g = { id: u.id, name: u.name, group: true, count: u.members.length, members: u.members.map((m) => m.id), memberPids: u.members.map((m) => m.pid), risk: u.risk, alive: u.alive,
                    parent: n.id, depth: depth + 1, x: (depth + 1) * dx, y: row * dy, rules: [], hidden: 0, hasKids: false };
        row += 1;
        maxDepth = Math.max(maxDepth, depth + 1);
        placed.push(g);
        placedKids.push(g);
        edges.push({ from: node, to: g });
      } else {
        const k = place(u, depth + 1, node);
        if (k) (placedKids.push(k), edges.push({ from: node, to: k }));
      }
    }
    if (!placedKids.length) {
      node.y = row * dy;
      row += 1;
    } else node.y = (placedKids[0].y + placedKids[placedKids.length - 1].y) / 2;
    return node;
  }

  roots.sort(order).forEach((r) => {
    place(r, 0, null);
    row += 0.7; // gap between separate trees
  });

  const bbox = placed.reduce(
    (b, n) => ({ x0: Math.min(b.x0, n.x - 14), y0: Math.min(b.y0, n.y - 16), x1: Math.max(b.x1, n.x + 200), y1: Math.max(b.y1, n.y + 16) }),
    { x0: Infinity, y0: Infinity, x1: -Infinity, y1: -Infinity },
  );
  const byPlacedId = new Map(placed.map((n) => [n.id, n]));
  return { nodes: placed, edges, bbox: placed.length ? bbox : { x0: 0, y0: 0, x1: 1, y1: 1 }, maxDepth, byId: byPlacedId, total: byId.size };
}

/** ids of every node with children below the roots, what "collapse all" folds. */
export function collapsibleIds(rawNodes) {
  const byId = indexNodes(rawNodes);
  const hasKids = new Set();
  for (const n of byId.values()) if (n.parent != null && byId.has(n.parent)) hasKids.add(n.parent);
  return [...hasKids].filter((id) => byId.get(id).parent != null && byId.has(byId.get(id).parent));
}
