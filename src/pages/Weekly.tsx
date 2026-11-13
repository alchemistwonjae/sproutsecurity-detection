import { Link } from '../lib/router';
import { useData } from '../lib/data';
import { LEVEL, fmtDate, logsourceLabel } from '../lib/labels';
import { LevelBadge, Loading, PageHead, StatusBadge, TacticChip } from '../components/ui';
import type { RuleSlim, Week } from '../types';

const weekRange = (w: string) => {
  const s = new Date(w + 'T00:00:00Z');
  const e = new Date(s);
  e.setUTCDate(e.getUTCDate() + 6);
  return `${fmtDate(w)} ~ ${fmtDate(e.toISOString().slice(0, 10))}`;
};

export function Weekly() {
  const weeks = useData<Week[]>('weekly.json');
  const idx = useData<RuleSlim[]>('rules-index.json');
  if (!weeks.data || !idx.data) return <Loading error={weeks.error || idx.error} />;
  const byId = new Map(idx.data.map((r) => [r.id, r]));
  const sorted = (ids: string[]) =>
    ids.map((i) => byId.get(i)).filter((r): r is RuleSlim => Boolean(r)).sort((a, b) => (LEVEL[b.l]?.rank ?? 0) - (LEVEL[a.l]?.rank ?? 0));

  return (
    <>
      <PageHead
        title="주간 신규 룰"
        lead="최근 8주 동안 SigmaHQ에 새로 들어온 룰과 수정된 룰입니다. 룰 파일에 적힌 작성일(date)·수정일(modified)을 기준으로 묶었으므로 SigmaHQ 릴리스 일정과 다를 수 있습니다."
      />
      {weeks.data.map((w) => {
        const added = sorted(w.added);
        const mod = sorted(w.modified);
        const hi = added.filter((r) => (LEVEL[r.l]?.rank ?? 0) >= 4).length;
        return (
          <section key={w.week} className="card week">
            <h2>{weekRange(w.week)}</h2>
            <p className="lead-line">
              새 룰 {added.length}개{added.length > 0 && `(높음 이상 ${hi}개)`} · 수정된 룰 {mod.length}개
            </p>
            {added.length > 0 && (
              <ul className="rule-list compact">
                {added.map((r) => (
                  <li key={r.id}>
                    <div className="rl-top">
                      <Link to={`/rules/${r.id}`} className="rl-title">{r.t}</Link>
                      <span className="rl-badges"><LevelBadge level={r.l} /><StatusBadge status={r.s} /></span>
                    </div>
                    <div className="rl-meta"><span>{logsourceLabel(r.p, r.cat, r.sv)}</span><span>{r.a.split(',')[0]}</span></div>
                    <div className="rl-chips">{r.tc.map((t) => <TacticChip key={t} t={t} />)}</div>
                  </li>
                ))}
              </ul>
            )}
            {mod.length > 0 && (
              <details>
                <summary>수정된 룰 {mod.length}개 보기</summary>
                <ul className="rule-list compact">
                  {mod.map((r) => (
                    <li key={r.id}>
                      <Link to={`/rules/${r.id}`} className="rl-title">{r.t}</Link>
                      <span className="rl-badges"><LevelBadge level={r.l} /></span>
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </section>
        );
      })}
      <p className="muted small">주간 요약의 한국어 설명은 룰 메타데이터로 자동 구성한 것입니다. 룰별 해설은 상세 화면에서 확인하세요.</p>
    </>
  );
}
