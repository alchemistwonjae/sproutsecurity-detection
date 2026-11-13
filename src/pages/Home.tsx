import { SUGGESTED } from '../lib/search';
import { useMemo } from 'react';
import { Link, navigate } from '../lib/router';
import { useData } from '../lib/data';
import { LEVEL, fmtDate, tacticKo } from '../lib/labels';
import { LevelBadge, Loading, StatusBadge, TacticChip } from '../components/ui';
import type { CveMap, Meta, RuleSlim, Week } from '../types';

// 공격 흐름 순서(정찰 → 영향)
const ORDER = [
  'reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence', 'privilege-escalation',
  'stealth', 'defense-impairment', 'credential-access', 'discovery', 'lateral-movement', 'collection',
  'command-and-control', 'exfiltration', 'impact',
];
const LEVELS = ['critical', 'high', 'medium', 'low', 'informational'];

function Flow() {
  // 로그 → Sigma 룰 → 경보 흐름 그림
  return (
    <svg className="flow" viewBox="0 0 440 250" role="img" aria-label="로그가 Sigma 룰과 맞으면 경보가 만들어지는 흐름">
      <g className="f-box">
        <rect x="8" y="40" width="112" height="170" rx="14" />
        <text x="64" y="68" textAnchor="middle" className="f-h">시스템 로그</text>
        {[92, 112, 132, 152, 172].map((y, i) => (
          <rect key={y} x="24" y={y} width={i === 2 ? 80 : 64 + (i % 3) * 8} height="9" rx="4" className={i === 2 ? 'f-hit' : 'f-line'} />
        ))}
      </g>
      <path d="M124 125h38" className="f-arrow" />
      <g className="f-box f-rule">
        <rect x="166" y="22" width="120" height="206" rx="14" />
        <text x="226" y="52" textAnchor="middle" className="f-h">Sigma 룰</text>
        <text x="182" y="86" className="f-code">title: LSASS</text>
        <text x="182" y="108" className="f-code">logsource:</text>
        <text x="194" y="126" className="f-code">windows</text>
        <text x="182" y="148" className="f-code">detection:</text>
        <text x="194" y="166" className="f-code">procdump -ma</text>
        <text x="182" y="188" className="f-code">level: high</text>
        <text x="226" y="214" textAnchor="middle" className="f-sub">공개 탐지 규칙</text>
      </g>
      <path d="M290 125h38" className="f-arrow" />
      <g className="f-box f-alert">
        <rect x="332" y="40" width="100" height="170" rx="14" />
        <text x="382" y="68" textAnchor="middle" className="f-h">경보</text>
        <circle cx="382" cy="122" r="26" className="f-dot" />
        <text x="382" y="131" textAnchor="middle" className="f-bang">!</text>
        <text x="382" y="184" textAnchor="middle" className="f-sub">해설·CVE 연결</text>
      </g>
    </svg>
  );
}

export function Home() {
  const meta = useData<Meta>('meta.json');
  const idx = useData<RuleSlim[]>('rules-index.json');
  const cves = useData<CveMap>('cves.json');
  const weeks = useData<Week[]>('weekly.json');

  const stats = useMemo(() => {
    if (!idx.data || !cves.data) return null;
    const kev = Object.values(cves.data).filter((v) => v.kev);
    const tac: Record<string, number> = {};
    const lv: Record<string, number> = {};
    for (const r of idx.data) {
      for (const t of r.tc) tac[t] = (tac[t] ?? 0) + 1;
      lv[r.l] = (lv[r.l] ?? 0) + 1;
    }
    return {
      rules: idx.data.length,
      withCve: idx.data.filter((r) => r.c.length).length,
      kevCovered: kev.filter((v) => v.rules.length).length,
      kevGap: kev.filter((v) => !v.rules.length).length,
      tac,
      lv,
    };
  }, [idx.data, cves.data]);

  if (!meta.data || !idx.data || !weeks.data || !stats) return <Loading error={meta.error || idx.error} />;
  const byId = new Map(idx.data.map((r) => [r.id, r]));
  const latest = weeks.data.find((w) => w.added.length > 0);
  const latestRules = (latest?.added ?? []).map((i) => byId.get(i)).filter((r): r is RuleSlim => Boolean(r)).slice(0, 8);
  const maxTac = Math.max(1, ...Object.values(stats.tac));
  const lvTotal = LEVELS.reduce((s, l) => s + (stats.lv[l] ?? 0), 0) || 1;

  return (
    <>
      <section className="hero">
        <div className="hero-text">
          <p className="eyebrow">Sigma 탐지 룰 허브</p>
          <h1>보안 로그에서 공격을 찾는 규칙,<br />한국어로 읽고 바로 찾아보세요</h1>
          <p className="lead">
            Sigma는 “이런 로그가 보이면 의심하라”를 적어 둔 공개 규칙입니다. 이 사이트는 룰마다 무엇을 잡고 언제 오탐이 나는지 한국어로 풀어 주고, MITRE ATT&amp;CK®·CVE·실제 악용 정보와 이어 드립니다.
          </p>
          <div className="chips" aria-label="추천 검색어">
            <span>추천 검색어</span>
            {SUGGESTED.map((w) => (
              <Link key={w} to={`/rules?q=${encodeURIComponent(w)}`} className="chip-link">{w}</Link>
            ))}
          </div>
          <p className="try">
            바로 보기: <Link to="/rules/5afee48e-67dd-4e03-a783-f74259dcf998">LSASS 덤프 룰 해설</Link> · <Link to="/rules?kev=1">실제 악용 CVE 룰</Link> · <Link to="/gaps">탐지 공백</Link>
          </p>
        </div>
        <div className="hero-art"><Flow /></div>
      </section>

      <section className="steps" aria-label="이 사이트로 할 수 있는 것">
        <Link to="/rules" className="step"><b>1</b><h3>룰을 찾고</h3><p>심각도·로그 종류·ATT&amp;CK 기법으로 {stats.rules.toLocaleString()}개 룰을 거릅니다.</p></Link>
        <Link to="/rules/5afee48e-67dd-4e03-a783-f74259dcf998" className="step"><b>2</b><h3>한국어로 이해하고</h3><p>무엇을 잡는지, 오탐은 언제 나는지, 무엇을 확인할지 풀어 줍니다.</p></Link>
        <Link to="/gaps" className="step"><b>3</b><h3>공백을 확인합니다</h3><p>실제 악용 중인데 룰이 없는 취약점을 한눈에 봅니다.</p></Link>
      </section>

      <section className="stats" aria-label="현황">
        <Link to="/rules" className="stat"><b>{stats.rules.toLocaleString()}</b><span>Sigma 룰</span></Link>
        <Link to="/rules?cve=1" className="stat"><b>{stats.withCve.toLocaleString()}</b><span>CVE가 연결된 룰</span></Link>
        <Link to="/rules?kev=1" className="stat"><b>{stats.kevCovered.toLocaleString()}</b><span>룰이 있는 실제 악용 CVE</span></Link>
        <Link to="/gaps" className="stat stat-warn"><b>{stats.kevGap.toLocaleString()}</b><span>룰이 없는 실제 악용 CVE</span></Link>
      </section>

      <section className="card">
        <div className="card-head">
          <h2>MITRE ATT&amp;CK® 전술별 룰 수</h2>
          <span className="muted small">공격 흐름 순서 · 누르면 해당 룰 목록</span>
        </div>
        <ul className="tactics">
          {ORDER.filter((t) => stats.tac[t]).map((t) => (
            <li key={t}>
              <Link to={`/rules?tactic=${t}`} className="tactic" style={{ ['--w' as string]: `${Math.round((stats.tac[t] / maxTac) * 100)}%` }}>
                <span className="t-name">{tacticKo(t)}</span>
                <span className="t-bar"><i /></span>
                <b>{stats.tac[t].toLocaleString()}</b>
              </Link>
            </li>
          ))}
        </ul>
        <h3 className="mt">심각도 분포</h3>
        <div className="lvbar" role="img" aria-label={LEVELS.map((l) => `${LEVEL[l].ko} ${stats.lv[l] ?? 0}개`).join(', ')}>
          {LEVELS.map((l) => (
            <Link key={l} to={`/rules?level=${l}`} className={`seg lv-${l}`} style={{ flexGrow: stats.lv[l] ?? 0 }} title={`${LEVEL[l].ko} ${stats.lv[l] ?? 0}개`} />
          ))}
        </div>
        <div className="legend">
          {LEVELS.map((l) => (
            <Link key={l} to={`/rules?level=${l}`} className={`lg lv-${l}`}><i />{LEVEL[l].ko} {(stats.lv[l] ?? 0).toLocaleString()} <small>({Math.round(((stats.lv[l] ?? 0) / lvTotal) * 100)}%)</small></Link>
          ))}
        </div>
      </section>

      <section className="card">
        <div className="card-head">
          <h2>최근 새 룰{latest && <small> {fmtDate(latest.week)} 주</small>}</h2>
          <Link to="/weekly">주간 신규 룰 전체 →</Link>
        </div>
        {latestRules.length === 0 ? (
          <p className="muted">최근 주에 새로 들어온 룰이 없습니다.</p>
        ) : (
          <ul className="rule-list compact">
            {latestRules.map((r) => (
              <li key={r.id}>
                <div className="rl-top">
                  <Link to={`/rules/${r.id}`} className="rl-title">{r.t}</Link>
                  <span className="rl-badges"><LevelBadge level={r.l} /><StatusBadge status={r.s} /></span>
                </div>
                <div className="rl-chips">{r.tc.map((t) => <TacticChip key={t} t={t} />)}</div>
              </li>
            ))}
          </ul>
        )}
      </section>

      <p className="muted small">
        SigmaHQ {meta.data.sigma.commit.slice(0, 7)}({meta.data.sigma.date}) 기준 · KEV 카탈로그 {meta.data.kev.catalogVersion}
      </p>
    </>
  );
}
