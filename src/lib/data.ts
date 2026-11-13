import { useEffect, useState } from 'react';

const cache = new Map<string, Promise<unknown>>();

export function load<T>(path: string): Promise<T> {
  let p = cache.get(path) as Promise<T> | undefined;
  if (!p) {
    p = fetch(`/data/${path}`).then((r) => {
      if (!r.ok) throw new Error(`${path}: ${r.status}`);
      return r.json() as Promise<T>;
    });
    p.catch(() => cache.delete(path));
    cache.set(path, p);
  }
  return p;
}

export function useData<T>(path: string | null): { data: T | null; error: boolean } {
  const [state, setState] = useState<{ path: string | null; data: T | null; error: boolean }>({ path: null, data: null, error: false });
  useEffect(() => {
    if (!path) return;
    let live = true;
    load<T>(path).then(
      (d) => live && setState({ path, data: d, error: false }),
      () => live && setState({ path, data: null, error: true }),
    );
    return () => {
      live = false;
    };
  }, [path]);
  // 경로가 바뀐 직후에는 이전 데이터를 보여 주지 않는다
  return state.path === path ? { data: state.data, error: state.error } : { data: null, error: false };
}
