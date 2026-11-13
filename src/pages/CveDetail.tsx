import { useEffect } from 'react';
import { Link } from '../lib/router';
import { useData } from '../lib/data';
import { fmtDate } from '../lib/labels';
import { KevBadge, LevelBadge, Loading, StatusBadge } from '../components/ui';
import type { CveMap, RuleSlim } from '../types';

export function CveDetail({ id }: { id: string }) {
  const cves = useData<CveMap>('cves.json');
  const idx = useData<RuleSlim[]>('rules-index.json');
  useEffect(() => {
    document.title = `${id} 탐지 룰 — Sprout Security Detection Hub`;
  }, [id]);
  if (!cves.data || !idx.data) return <Loading error={cves.error || idx.error} />;
  const c = cves.data[id];
  if (!c) return <p className="empty">{id}는 이 사이트의 데이터에 없습니다. 룰이 참조하지 않고 KEV에도 없는 CVE입니다. <a href={`https://nvd.nist.gov/vuln/detail/${id}`} target="_blank" rel="noreferrer">NVD에서 보기 ↗</a></p>;
  const rules = c.rules.map((rid) => idx.data!.find((r) => r.id === rid)).filter((r): r is RuleSlim => Boolean(r));

  return (
    <article className="detail">
      <p className="crumb"><Link to="/rules">룰 카탈로그</Link> › CVE</p>
      <h1>{id} {c.kev && <KevBadge />}</h1>

      <section className="card">
        <h2>탐지 룰 {rules.length}개</h2>
        {rules.length ? (
          <ul className="rule-list compact">
            {rules.map((r) => (
              <li key={r.id}>
                <Link to={`/rules/${r.id}`} className="rl-title">{r.t}</Link>
                <span className="rl-badges"><LevelBadge level={r.l} /><StatusBadge status={r.s} /></span>
              </li>
            ))}
          </ul>
        ) : (
          <p>{c.kev ? '이 CVE는 실제 악용이 확인됐지만, 이 사이트가 수집한 Sigma 룰 중에는 CVE를 명시한 룰이 없습니다(탐지 공백 후보). 룰이 없다고 탐지가 불가능하다는 뜻은 아닙니다.' : '연결된 룰이 없습니다.'}</p>
        )}
      </section>

      {c.kev && (
        <section className="card">
          <h2>CISA KEV 정보</h2>
          <p className="lead-line">{c.kev.name}</p>
          <dl className="kv">
            <dt>제품</dt><dd>{c.kev.vendor} {c.kev.product}</dd>
            <dt>KEV 등재일</dt><dd>{fmtDate(c.kev.added)}</dd>
            <dt>조치 기한(미국 연방기관)</dt><dd>{fmtDate(c.kev.due)}</dd>
            <dt>랜섬웨어 사용</dt><dd>{c.kev.ransomware ? '알려짐' : '알려지지 않음'}</dd>
          </dl>
          <blockquote lang="en" className="orig"><small>설명(영문, CISA)</small>{c.kev.desc}</blockquote>
        </section>
      )}

      <section className="card">
        <h2>NVD</h2>
        {c.nvd ? (
          <>
            <dl className="kv">
              <dt>CVSS</dt><dd>{c.nvd.enriched ? `${c.nvd.score} (${c.nvd.severity})` : 'NVD가 아직 점수를 보강하지 않았습니다'}</dd>
              <dt>공개일</dt><dd>{fmtDate(c.nvd.published ?? '')}</dd>
            </dl>
            <blockquote lang="en" className="orig"><small>설명(영문, NVD)</small>{c.nvd.desc}</blockquote>
          </>
        ) : (
          <p className="muted">이번 빌드에서는 NVD 정보를 수집하지 않았습니다. 빈 칸은 '없다'가 아니라 '수집하지 않았다'는 뜻입니다.</p>
        )}
        <p className="small">
          링크 아웃: <a href={`https://nvd.nist.gov/vuln/detail/${id}`} target="_blank" rel="noreferrer">NVD ↗</a> ·{' '}
          <a href={`https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${id}`} target="_blank" rel="noreferrer">CISA KEV ↗</a> ·{' '}
          <a href={`https://otx.alienvault.com/indicator/cve/${id}`} target="_blank" rel="noreferrer">AlienVault OTX ↗</a>
        </p>
      </section>
    </article>
  );
}
