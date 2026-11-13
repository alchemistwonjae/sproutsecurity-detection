import { matchQuery } from '../lib/search';
import { useMemo } from 'react';
import { Link, navigate } from '../lib/router';
import { useData } from '../lib/data';
import { LEVEL, STATUS, fmtDate, logsourceLabel, slimHay, tacticKo } from '../lib/labels';
import { CveChip, LevelBadge, Loading, PageHead, StatusBadge, TacticChip } from '../components/ui';
import type { Attack, CveMap, RuleSlim } from '../types';

const PER = 50;

export function Rules({ search }: { search: string }) {
  const idx = useData<RuleSlim[]>('rules-index.json');
  const attack = useData<Attack>('attack.json');
  const cves = useData<CveMap>('cves.json');

  const sp = new URLSearchParams(search);
  const f = {
    q: sp.get('q') ?? '',
    level: sp.get('level') ?? '',
    status: sp.get('status') ?? '',
    tactic: sp.get('tactic') ?? '',
    tech: (sp.get('tech') ?? '').toUpperCase(),
    product: sp.get('product') ?? '',
    cat: sp.get('cat') ?? '',
    cve: sp.get('cve') === '1',
    kev: sp.get('kev') === '1',
  };
  const prods = f.product.split(',').filter(Boolean);
  const lvs = f.level.split(',').filter(Boolean);
  const page = Math.max(1, Number(sp.get('page') ?? 1) || 1);

  const set = (patch: Record<string, string | boolean>, keepPage = false) => {
    const n = new URLSearchParams(search);
    for (const [k, v] of Object.entries(patch)) {
      if (v === '' || v === false) n.delete(k);
      else n.set(k, v === true ? '1' : v);
    }
    if (!keepPage) n.delete('page');
    const s = n.toString();
    navigate('/rules' + (s ? `?${s}` : ''), true);
  };

  const kevSet = useMemo(() => new Set(Object.entries(cves.data ?? {}).filter(([, v]) => v.kev).map(([k]) => k)), [cves.data]);
  const techName = (t: string) => attack.data?.techniques[t]?.name ?? '';
  const hay = useMemo(() => (idx.data ?? []).map((r) => slimHay(r) + ' ' + r.k.map((t) => techName(t).toLowerCase()).join(' ')), [idx.data, attack.data]);
  const products = useMemo(() => [...new Set((idx.data ?? []).map((r) => r.p).filter(Boolean))].sort(), [idx.data]);

  const rows = useMemo(() => {
    if (!idx.data) return [];
    const ql = f.q.trim().toLowerCase();
    return idx.data.filter((r, i) => {
      if (ql && !matchQuery(ql, hay[i])) return false;
      if (lvs.length && !lvs.includes(r.l)) return false;
      if (f.cat && r.cat !== f.cat) return false;
      if (f.status && r.s !== f.status) return false;
      if (f.tactic && !r.tc.includes(f.tactic)) return false;
      if (f.tech && !r.k.some((t) => t === f.tech || t.startsWith(f.tech + '.'))) return false;
      if (prods.length && !prods.includes(r.p)) return false;
      if (f.cve && !r.c.length) return false;
      if (f.kev && !r.c.some((c) => kevSet.has(c))) return false;
      return true;
    });
  }, [idx.data, hay, search, kevSet]);

  if (!idx.data) return <Loading error={idx.error} />;
  const pages = Math.max(1, Math.ceil(rows.length / PER));
  const cur = Math.min(page, pages);
  const slice = rows.slice((cur - 1) * PER, cur * PER);
  const goPage = (p: number) => {
    const n = new URLSearchParams(search);
    n.set('page', String(p));
    navigate('/rules?' + n.toString());
    window.scrollTo(0, 0);
  };
  const active = Object.entries({ 검색: f.q, 심각도: f.level, 상태: f.status, 전술: f.tactic, 기법: f.tech, 로그: f.product, 로그종류: f.cat }).filter(([, v]) => v);

  return (
    <>
      <PageHead title="룰 카탈로그" lead={`SigmaHQ 공개 탐지 룰 ${idx.data.length.toLocaleString()}개를 심각도·MITRE ATT&CK®·로그 소스·CVE로 걸러 볼 수 있습니다.`} />
      <section className="filters" aria-label="필터">
        <label>
          <span>검색</span>
          <input type="search" value={f.q} placeholder="제목, CVE, 기법, 작성자" onChange={(e) => set({ q: e.target.value }, false)} />
        </label>
        <label>
          <span>심각도</span>
          <select value={lvs.length === 1 ? lvs[0] : ''} onChange={(e) => set({ level: e.target.value })}>
            <option value="">{lvs.length > 1 ? `여러 개(${lvs.length})` : '전체'}</option>
            {['critical', 'high', 'medium', 'low', 'informational'].map((l) => (
              <option key={l} value={l}>{LEVEL[l].ko}</option>
            ))}
          </select>
        </label>
        <label>
          <span>상태</span>
          <select value={f.status} onChange={(e) => set({ status: e.target.value })}>
            <option value="">전체</option>
            {['stable', 'test', 'experimental'].map((s) => (
              <option key={s} value={s}>{STATUS[s].ko}</option>
            ))}
          </select>
        </label>
        <label>
          <span>ATT&amp;CK 전술</span>
          <select value={f.tactic} onChange={(e) => set({ tactic: e.target.value })}>
            <option value="">전체</option>
            {(attack.data?.tactics ?? []).map((t) => (
              <option key={t.short} value={t.short}>{tacticKo(t.short)} ({t.name})</option>
            ))}
          </select>
        </label>
        <label>
          <span>로그 제품</span>
          <select value={prods.length === 1 ? prods[0] : ''} onChange={(e) => set({ product: e.target.value })}>
            <option value="">{prods.length > 1 ? `여러 개(${prods.length})` : '전체'}</option>
            {products.map((p) => (
              <option key={p} value={p}>{p}</option>
            ))}
          </select>
        </label>
        <label className="check">
          <input type="checkbox" checked={f.cve} onChange={(e) => set({ cve: e.target.checked })} /> CVE 연결 룰만
        </label>
        <label className="check">
          <input type="checkbox" checked={f.kev} onChange={(e) => set({ kev: e.target.checked })} /> 실제 악용(KEV) CVE 연결만
        </label>
      </section>

      <div className="result-bar">
        <strong>{rows.length.toLocaleString()}개</strong>
        {active.map(([k, v]) => (
          <span key={k} className="tag-on">{k}: {v}</span>
        ))}
        {(active.length > 0 || f.cve || f.kev) && (
          <button type="button" className="link-btn" onClick={() => navigate('/rules', true)}>필터 초기화</button>
        )}
      </div>

      {slice.length === 0 ? (
        <p className="empty">조건에 맞는 룰이 없습니다.</p>
      ) : (
        <ul className="rule-list">
          {slice.map((r) => (
            <li key={r.id}>
              <div className="rl-top">
                <Link to={`/rules/${r.id}`} className="rl-title">{r.t}</Link>
                <span className="rl-badges"><LevelBadge level={r.l} /><StatusBadge status={r.s} /></span>
              </div>
              <div className="rl-meta">
                <span>{logsourceLabel(r.p, r.cat, r.sv)}</span>
                <span>작성 {fmtDate(r.d)}</span>
                {r.m && r.m !== r.d && <span>수정 {fmtDate(r.m)}</span>}
                <span>{r.a.split(',')[0]}</span>
              </div>
              <div className="rl-chips">
                {r.tc.map((t) => <TacticChip key={t} t={t} />)}
                {r.k.map((t) => (
                  <Link key={t} to={`/rules?tech=${t}`} className="chip chip-soft" title={techName(t)}>{t}</Link>
                ))}
                {r.c.map((c) => <CveChip key={c} id={c} kev={kevSet.has(c)} />)}
              </div>
            </li>
          ))}
        </ul>
      )}

      {pages > 1 && (
        <nav className="pager" aria-label="페이지">
          <button type="button" disabled={cur <= 1} onClick={() => goPage(cur - 1)}>이전</button>
          <span>{cur} / {pages}</span>
          <button type="button" disabled={cur >= pages} onClick={() => goPage(cur + 1)}>다음</button>
        </nav>
      )}
    </>
  );
}
