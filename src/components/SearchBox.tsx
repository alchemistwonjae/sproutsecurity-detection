import { useMemo, useRef, useState, type ReactNode } from 'react';
import { navigate } from '../lib/router';
import { useData } from '../lib/data';
import { LEVEL, TACTIC_KO } from '../lib/labels';
import { SUGGESTED, expandWord } from '../lib/search';
import type { RuleSlim } from '../types';

interface Sug { key: string; ico: string; main: string; sub?: string; tag?: string; to: string; kind: string }
type CveMap = Record<string, unknown>;
interface Attack { tactics: { short: string; name: string; id: string }[]; techniques: Record<string, { name: string }> }

const mark = (text: string, q: string): ReactNode => {
  const i = q ? text.toLowerCase().indexOf(q.toLowerCase()) : -1;
  if (i < 0) return text;
  return (<>{text.slice(0, i)}<mark>{text.slice(i, i + q.length)}</mark>{text.slice(i + q.length)}</>);
};

const LV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, informational: 4 };

export function SearchBox({ variant, placeholder, autoFocus }: { variant: 'gnb' | 'hero'; placeholder: string; autoFocus?: boolean }) {
  const [q, setQ] = useState('');
  const [focus, setFocus] = useState(false);
  const [active, setActive] = useState(-1);
  const [armed, setArmed] = useState(false); // 처음 포커스되면 데이터 로드 시작
  const ref = useRef<HTMLFormElement>(null);
  const idx = useData<RuleSlim[]>(armed ? 'rules-index.json' : null);
  const cves = useData<CveMap>(armed ? 'cves.json' : null);
  const atk = useData<Attack>(armed ? 'attack.json' : null);
  const id = `sug-${variant}`;

  const sugs = useMemo<Sug[]>(() => {
    const t = q.trim();
    if (!t) return SUGGESTED.map((s) => ({ key: 'r' + s, ico: '↗', main: s, sub: '추천 검색어', to: `/rules?q=${encodeURIComponent(s)}`, kind: 'rec' }));
    const tl = t.toLowerCase();
    const out: Sug[] = [{ key: 'q', ico: '⌕', main: `‘${t}’ 검색`, sub: '룰 카탈로그에서 전체 검색', to: `/rules?q=${encodeURIComponent(t)}`, kind: 'all' }];
    const words = tl.split(/\s+/).filter(Boolean);

    if (idx.data) {
      const hit: { r: RuleSlim; score: number }[] = [];
      for (const r of idx.data) {
        const title = r.t.toLowerCase();
        const ok = words.every((w) => expandWord(w).some((x) => title.includes(x)));
        if (!ok) continue;
        const score = (title.startsWith(tl) ? 0 : title.includes(tl) ? 1 : 2) * 10 + (LV_RANK[r.l] ?? 5);
        hit.push({ r, score });
      }
      hit.sort((a, b) => a.score - b.score);
      for (const { r } of hit.slice(0, 5)) out.push({ key: r.id, ico: '룰', main: r.t, sub: `${LEVEL[r.l]?.ko ?? r.l}${r.c.length ? ' · ' + r.c.slice(0, 2).join(', ') : ''}`, to: `/rules/${r.id}`, kind: 'rule' });
    }
    if (cves.data && /cve|\d{4}-\d/i.test(t)) {
      const key = tl.replace(/^cve-?/, '');
      let n = 0;
      for (const c of Object.keys(cves.data)) {
        if (c.toLowerCase().includes('cve-' + key) || c.toLowerCase().includes(key)) {
          out.push({ key: c, ico: 'CVE', main: c, sub: '취약점 · 관련 룰 보기', to: `/cves/${c}`, kind: 'inc' });
          if (++n >= 3) break;
        }
      }
    }
    if (atk.data) {
      let n = 0;
      for (const [tid, v] of Object.entries(atk.data.techniques)) {
        if (tid.toLowerCase().startsWith(tl) || (t.length >= 2 && v.name.toLowerCase().includes(tl))) {
          out.push({ key: tid, ico: 'T', main: `${tid} ${v.name}`, sub: 'MITRE ATT&CK® 기법', to: `/rules?tech=${tid}`, kind: 'tech' });
          if (++n >= 3) break;
        }
      }
      for (const ta of atk.data.tactics) {
        const ko = TACTIC_KO[ta.short] ?? '';
        if (ta.name.toLowerCase().includes(tl) || ko.includes(t) || ta.id.toLowerCase() === tl) {
          out.push({ key: ta.short, ico: 'TA', main: `${ko || ta.name} (${ta.name})`, sub: '전술', to: `/rules?tactic=${ta.short}`, kind: 'tac' });
        }
      }
    }
    return out.slice(0, 10);
  }, [q, idx.data, cves.data, atk.data]);

  const open = focus && sugs.length > 0;
  const go = (to: string) => { setFocus(false); setActive(-1); navigate(to); };
  const submit = () => {
    const t = q.trim();
    go(t ? `/rules?q=${encodeURIComponent(t)}` : '/rules');
  };

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setFocus(true); setActive((a) => (a + 1) % sugs.length); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); setActive((a) => (a <= 0 ? sugs.length - 1 : a - 1)); }
    else if (e.key === 'Escape') { setFocus(false); setActive(-1); }
    else if (e.key === 'Enter' && open && active >= 0) { e.preventDefault(); go(sugs[active].to); }
  };

  const input = (
    <input
      type="search"
      name="q"
      role="combobox"
      aria-label="룰 검색"
      aria-expanded={open}
      aria-controls={id}
      aria-autocomplete="list"
      aria-activedescendant={active >= 0 ? `${id}-${active}` : undefined}
      autoComplete="off"
      autoFocus={autoFocus}
      placeholder={placeholder}
      value={q}
      onChange={(e) => { setQ(e.target.value); setActive(-1); }}
      onFocus={() => { setArmed(true); setFocus(true); }}
      onBlur={() => setTimeout(() => setFocus(false), 120)}
      onKeyDown={onKey}
    />
  );

  return (
    <form ref={ref} className={`gsearch ${variant === 'hero' ? 'hero-search' : ''}`} role="search" onSubmit={(e) => { e.preventDefault(); if (active < 0) submit(); }}>
      {variant === 'hero' ? input : <label><span className="sr">룰 검색</span>{input}</label>}
      {variant === 'hero' && <button type="submit">검색</button>}
      {open && (
        <ul className="sug" id={id} role="listbox" onMouseDown={(e) => e.preventDefault()}>
          {sugs.map((s, i) => (
            <li key={s.key} id={`${id}-${i}`} role="option" aria-selected={i === active} className={`${i === active ? 'on' : ''} ${s.kind === 'inc' ? 'inc' : ''}`} onMouseEnter={() => setActive(i)} onClick={() => go(s.to)}>
              <span className="sug-ico" aria-hidden="true">{s.ico}</span>
              <span className="sug-main"><b>{mark(s.main, q.trim())}</b>{s.sub && <small>{s.sub}</small>}</span>
            </li>
          ))}
        </ul>
      )}
    </form>
  );
}
