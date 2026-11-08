import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Fetch hook, stale-while-revalidate.
 *   data    last good result, kept if a refresh fails
 *   error   latest failure, cleared on the next success
 *   loading true only until the first data arrives
 *   stale   error is set but old data is still on screen
 * Polls while the tab is visible, refreshes when it comes back, drops late responses.
 */
export function usePolled(fetcher, deps, { interval = 0, enabled = true } = {}) {
  const [state, setState] = useState({ data: null, error: null, loading: true, at: null });
  const fetchRef = useRef(fetcher);
  fetchRef.current = fetcher;
  const seq = useRef(0);
  const ctrl = useRef(null);

  const run = useCallback(async () => {
    const id = ++seq.current;
    ctrl.current?.abort();
    const c = new AbortController();
    ctrl.current = c;
    try {
      const data = await fetchRef.current(c.signal);
      if (id === seq.current) setState({ data, error: null, loading: false, at: Date.now() });
    } catch (error) {
      if (c.signal.aborted || id !== seq.current) return;
      setState((s) => ({ ...s, error, loading: false }));
    }
  }, []);

  useEffect(() => {
    if (!enabled) return undefined;
    setState((s) => (s.data == null ? { ...s, loading: true } : s));
    run();
    let t;
    const tick = () => {
      if (!document.hidden) run();
    };
    if (interval > 0) t = setInterval(tick, interval * 1000);
    const vis = () => !document.hidden && run();
    document.addEventListener("visibilitychange", vis);
    return () => {
      clearInterval(t);
      document.removeEventListener("visibilitychange", vis);
      ctrl.current?.abort();
      seq.current++;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, interval, enabled, run]);

  return { ...state, stale: !!state.error && state.data != null, reload: run };
}

export function useDebounced(value, ms = 250) {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms);
    return () => clearTimeout(t);
  }, [value, ms]);
  return v;
}

/** True while the user is typing, so single-key shortcuts should be ignored. */
export function isTyping(e) {
  const t = e.target;
  if (!t || !t.tagName) return false;
  return t.isContentEditable || ["INPUT", "TEXTAREA", "SELECT"].includes(t.tagName);
}

export function useKeys(handler, deps = []) {
  const ref = useRef(handler);
  ref.current = handler;
  useEffect(() => {
    const f = (e) => ref.current(e);
    window.addEventListener("keydown", f);
    return () => window.removeEventListener("keydown", f);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
}
