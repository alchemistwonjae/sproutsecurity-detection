import { useMemo, useState } from 'react';
import { Link } from '../lib/router';
import { useData } from '../lib/data';
import { tacticKo } from '../lib/labels';
import { Loading, PageHead } from '../components/ui';
import type { Attack, RuleSlim } from '../types';

const ORDER = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence', 'privilege-escalation',
  'stealth', 'defense-impairment', 'credential-access', 'discovery', 'lateral-movement', 'collection',
  'command-and-control', 'exfiltration', 'impact',
];
const PRESETS: { label: string; prods: string[] }[] = [
  { label: 'Windows PC·서버', prods: ['windows'] },
  { label: 'Windows + Linux', prods: ['windows', 'linux'] },
  { label: '클라우드(AWS·Azure·GCP)', prods: ['aws', 'azure', 'gcp'] },
  { label: 'SaaS·ID(M365·Okta·GitHub)', prods: ['m365', 'okta', 'github', 'onelogin'] },
];

export function Coverage() {
  const idx = useData<RuleSlim[]>('rules-index.json');
  const attack = useData<Attack>('attack.json');
  const [sel, setSel] = useState<string[]>(['windows']);
  const [stableOnly, setStableOnly] = useState(false);
  const [noHunt, setNoHunt] = useState(false);

  const products = useMemo(() => {
    const m: Record<string, number> = {};
    for (const r of idx.data ?? []) if (r.p) m[r.p] = (m[r.p] ?? 0) + 1;
    return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 14);
  }, [idx.data]);

  const calc = useMemo(() => {
    if (!idx.data || !attack.data) return null;
    const count: Record<string, number> = {};
    for (const r of idx.data) {
      if (!sel.includes(r.p)) continue;
      if (stableOnly && r.s !== 'stable') continue;
      if (noHunt && r.kind === 'hunting') continue;
      for (const t of r.k) {
        const top = t.split('.')[0];
        count[top] = (count[top] ?? 0) + 1;
      }
    }
    const tops = Object.entries(attack.data.techniques).filter(([id]) => !id.includes('.'));
    const cols = ORDER.map((tac) => ({
      tac,
      items: tops
        .filter(([, v]) => v.tactics.includes(tac))
        .map(([id, v]) => ({ id, name: v.name, n: count[id] ?? 0 }))
        .sort((a, b) => b.n - a.n || a.id.localeCompare(b.id)),
    })).filter((c) => c.items.length);
    const covered = tops.filter(([id]) => count[id]).length;
    return { cols, covered, total: tops.length };
  }, [idx.data, attack.data, sel, stableOnly, noHunt]);

  if (!idx.data || !attack.data || !calc) return <Loading error={idx.error || attack.error} />;
  const toggle = (p: string) => setSel((s) => (s.includes(p) ? s.filter((x) => x !== p) : [...s, p]));
  const q = (id: string) => `/rules?tech=${id}&product=${sel.join(',')}`;
  const pct = Math.round((calc.covered / calc.total) * 100);

  return (
    <>
      <PageHead
        title="내 로그 기준 MITRE ATT&CK® 커버리지 지도"
        lead="내가 수집하는 로그를 고르면, 그 로그를 대상으로 하는 Sigma 룰이 있는 ATT&CK 기법이 칠해집니다. 우리 동네 CCTV가 어느 구역을 비추는지 지도에 표시해 보는 것과 같아요."
      />
      <section className="filters cov-filters">
        <div className="cov-group">
          <span className="cov-label">자주 쓰는 조합</span>
          <div className="cov-chips">
            {PRESETS.map((p) => (
              <button key={p.label} type="button" className="chip-btn" onClick={() => setSel(p.prods)}>{p.label}</button>
            ))}
          </div>
        </div>
        <div className="cov-group">
          <span className="cov-label">수집하는 로그(복수 선택)</span>
          <div className="cov-chips">
            {products.map(([p, n]) => (
              <button key={p} type="button" aria-pressed={sel.includes(p)} className={`chip-btn${sel.includes(p) ? ' on' : ''}`} onClick={() => toggle(p)}>
                {p} <small>{n}</small>
              </button>
            ))}
          </div>
        </div>
        <label className="check"><input type="checkbox" checked={stableOnly} onChange={(e) => setStableOnly(e.target.checked)} /> 안정(stable) 룰만</label>
        <label className="check"><input type="checkbox" checked={noHunt} onChange={(e) => setNoHunt(e.target.checked)} /> 헌팅용 룰 제외</label>
      </section>

      <div className="cov-sum">
        <strong>{calc.covered}</strong> / {calc.total}개 기법에 룰이 있습니다 ({pct}%)
        <span className="muted small"> — 선택한 로그: {sel.length ? sel.join(', ') : '없음'}</span>
      </div>
      <p className="notice">
        참고용입니다. 룰이 있다고 그 기법을 막거나 항상 탐지한다는 뜻이 아니고, 룰이 없다고 위험하다는 뜻도 아닙니다. MITRE ATT&amp;CK®는 가능한 모든 행동을 담지 않으며, 룰이 실제로 동작하려면 해당 로그가 수집되고 필드가 맞아야 합니다. 기법 하나를 여러 전술이 함께 쓰므로 같은 기법이 여러 열에 나옵니다.
      </p>

      <div className="matrix" role="region" aria-label="ATT&CK 매트릭스" tabIndex={0}>
        {calc.cols.map((c) => (
          <div key={c.tac} className="mcol">
            <h3>{tacticKo(c.tac)}<small>{c.items.filter((i) => i.n).length}/{c.items.length}</small></h3>
            {c.items.map((t) => (
              <Link key={t.id} to={q(t.id)} className={`mcell m${t.n === 0 ? 0 : t.n < 3 ? 1 : t.n < 8 ? 2 : 3}`} title={`${t.id} ${t.name} — 룰 ${t.n}개`}>
                <b>{t.id}</b>
                <span>{t.name}</span>
                {t.n > 0 && <i>{t.n}</i>}
              </Link>
            ))}
          </div>
        ))}
      </div>
      <p className="legend small">
        <span className="mcell m0 sw" /> 룰 없음 <span className="mcell m1 sw" /> 1~2개 <span className="mcell m2 sw" /> 3~7개 <span className="mcell m3 sw" /> 8개 이상
      </p>
    </>
  );
}
