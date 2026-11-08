import { useSyncExternalStore } from "react";

let items = [];
let seq = 0;
const subs = new Set();
const emit = () => subs.forEach((f) => f());

export function toast({ title, body = "", tone = "info", ms = 5000, action } = {}) {
  const id = ++seq;
  // identical consecutive messages collapse instead of stacking
  if (items.some((t) => t.title === title && t.body === body)) return id;
  items = [...items.slice(-3), { id, title, body, tone, action }];
  emit();
  if (ms) setTimeout(() => dismiss(id), ms);
  return id;
}

export function dismiss(id) {
  items = items.filter((t) => t.id !== id);
  emit();
}

export function useToasts() {
  return useSyncExternalStore(
    (f) => (subs.add(f), () => subs.delete(f)),
    () => items,
  );
}
