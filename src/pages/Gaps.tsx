import { useMemo } from 'react';
import { Link, navigate } from '../lib/router';
import { useData } from '../lib/data';
import { fmtDate } from '../lib/labels';
import { KevBadge, Loading, PageHead } from '../components/ui';
import type { CveMap } from '../types';

const PER = 50;

export function Gaps({ search }: { search: string }) {
  const cves = useData<CveMap>('cves.json');
  const sp = new URLSearchParams(search);
  const q = sp.get('q') ?? '';
  const ran = sp.get('ransomware') === '1';
  const page = Math.max(1, Number(sp.get('page') ?? 1) || 1);

  const all = useMemo(
    () =>
      Object.entries(cves.data ?? {})
        .filter(([, v]) => v.kev && v.rules.length === 0)
        .map(([id, v]) => ({ id, ...v.kev! }))
        .sort((a, b) => (a.added < b.added ? 1 : a.added > b.added ? -1 : 0)),
    [cves.data],
  );
  const covered = useMemo(() => Object.values(cves.data ?? {}).filter((v) => v.kev && v.rules.length > 0).length, [cves.data]);
  const rows = useMemo(() => {
    const ql = q.trim().toLowerCase();
    return all.filter((r) => (!ran || r.ransomware) && (!ql || `${r.id} ${r.vendor} ${r.product} ${r.name}`.toLowerCase().includes(ql)));
  }, [all, q, ran]);

  const vendors = useMemo(() => {
    const m: Record<string, number> = {};
    for (const r of all) m[r.vendor] = (m[r.vendor] ?? 0) + 1;
    return Object.entries(m).sort((a, b) => b[1] - a[1]).slice(0, 14);
  }, [all]);

  if (!cves.data) return <Loading error={cves.error} />;
  const set = (patch: Record<string, string | boolean>) => {
    const n = new URLSearchParams(search);
    for (const [k, v] of Object.entries(patch)) (v === '' || v === false ? n.delete(k) : n.set(k, v === true ? '1' : v));
    if (!('page' in patch)) n.delete('page');
    const s = n.toString();
    navigate('/gaps' + (s ? `?${s}` : ''), true);
  };
  const pages = Math.max(1, Math.ceil(rows.length / PER));
  const cur = Math.min(page, pages);

  return (
    <>
      <PageHead
        title="탐지 공백: 실제 악용 중인데 Sigma 룰이 없는 CVE"
        lead={`CISA KEV에 올라 실제 악용이 확인된 CVE ${all.length + covered}건 중 ${all.length.toLocaleString()}건은 이 사이트가 수집한 Sigma 룰이 CVE를 명시하지 않습니다. 룰 작성·기여의 우선순위를 가늠하는 참고용입니다.`}
      />
      <p className="notice">
        ‘룰 없음’은 다른 탐지 수단(EDR·IPS·벤더 시그니처)이 없다는 뜻이 아닙니다. CVE 연결은 룰의 태그·제목·설명·참고 링크에서 CVE 번호를 추출한 결과라 누락이 있을 수 있습니다. 취약 제품이 Sigma로 탐지하기 어려운 종류(예: 네트워크 장비 내부 동작)일 수도 있습니다.
      </p>
      <section className="filters">
        <label>
          <span>검색</span>
          <input type="search" value={q} placeholder="제품·벤더·CVE" onChange={(e) => set({ q: e.target.value })} />
        </label>
        <label className="check">
          <input type="checkbox" checked={ran} onChange={(e) => set({ ransomware: e.target.checked })} /> 랜섬웨어 사용이 알려진 것만
        </label>
      </section>
      <section className="card">
        <h2>벤더별 공백 (많은 순)</h2>
        <p className="muted small">누르면 해당 벤더로 검색합니다. 룰을 먼저 써 볼 제품을 고를 때 참고하세요.</p>
        <div className="cov-chips">
          {vendors.map(([v, n]) => (
            <button key={v} type="button" className={`chip-btn${q === v ? ' on' : ''}`} onClick={() => set({ q: q === v ? '' : v })}>{v} <small>{n}</small></button>
          ))}
        </div>
        <p className="small"><Link to="/drafts">룰 초안 보기 →</Link> (Ivanti·Cisco ASA·Fortinet 3건)</p>
      </section>
      <div className="result-bar"><strong>{rows.length.toLocaleString()}건</strong></div>
      <ul className="rule-list">
        {rows.slice((cur - 1) * PER, cur * PER).map((r) => (
          <li key={r.id}>
            <div className="rl-top">
              <Link to={`/cves/${r.id}`} className="rl-title">{r.id} · {r.vendor} {r.product}</Link>
              <span className="rl-badges"><KevBadge />{r.ransomware && <span className="badge lv-high">랜섬웨어</span>}</span>
            </div>
            <p className="gap-name">{r.name}</p>
            <div className="rl-meta"><span>KEV 등재 {fmtDate(r.added)}</span></div>
          </li>
        ))}
      </ul>
      {pages > 1 && (
        <nav className="pager" aria-label="페이지">
          <button type="button" disabled={cur <= 1} onClick={() => { set({ page: String(cur - 1) }); window.scrollTo(0, 0); }}>이전</button>
          <span>{cur} / {pages}</span>
          <button type="button" disabled={cur >= pages} onClick={() => { set({ page: String(cur + 1) }); window.scrollTo(0, 0); }}>다음</button>
        </nav>
      )}
    </>
  );
}
