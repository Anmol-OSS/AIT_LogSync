import { useCallback, useEffect, useState } from "react";

export interface AsyncState<T> {
  data: T | undefined;
  error: string | undefined;
  reload: () => void;
}

/**
 * Run an async loader when `deps` change. With `refreshMs` it re-runs on a timer
 * (the dashboard polls; no websockets needed). Keeps the previous data while
 * refreshing so screens do not flicker.
 */
export function useAsync<T>(load: () => Promise<T>, deps: unknown[], refreshMs?: number): AsyncState<T> {
  const [data, setData] = useState<T>();
  const [error, setError] = useState<string>();
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    let cancelled = false;
    load().then(
      (v) => { if (!cancelled) { setData(v); setError(undefined); } },
      (e: unknown) => { if (!cancelled) setError(e instanceof Error ? e.message : String(e)); },
    );
    return () => { cancelled = true; };
  }, [...deps, tick]);

  useEffect(() => {
    if (!refreshMs) return;
    const id = setInterval(reload, refreshMs);
    return () => clearInterval(id);
  }, [refreshMs, reload]);

  return { data, error, reload };
}
