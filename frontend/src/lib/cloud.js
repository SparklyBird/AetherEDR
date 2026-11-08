// Scalloped outline around a node. Seeded, so a node keeps the same wobble between renders.
export function cloudPath(cx, cy, r, seed = 1, bumps = 10) {
  let s = (Math.abs(Number(seed) || 1) * 9301 + 49297) % 233280;
  const rnd = () => ((s = (s * 9301 + 49297) % 233280) / 233280);
  const pts = [];
  for (let i = 0; i < bumps; i++) {
    const a = (i / bumps) * Math.PI * 2 + (rnd() - 0.5) * 0.14;
    const rr = r * (1 + (rnd() - 0.5) * 0.14);
    pts.push([cx + rr * Math.cos(a), cy + rr * Math.sin(a)]);
  }
  let d = `M${pts[0][0].toFixed(1)},${pts[0][1].toFixed(1)}`;
  for (let i = 0; i < bumps; i++) {
    const [qx, qy] = pts[(i + 1) % bumps];
    const [px, py] = pts[i];
    const ar = Math.hypot(qx - px, qy - py) * 0.6;
    d += `A${ar.toFixed(1)},${ar.toFixed(1)} 0 0 1 ${qx.toFixed(1)},${qy.toFixed(1)}`;
  }
  return `${d}Z`;
}
