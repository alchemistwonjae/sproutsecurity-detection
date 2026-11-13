import { useEffect } from 'react';
import { Link } from '../lib/router';
import { useData } from '../lib/data';
import { STATUS, autoSummary, fmtDate, KIND_KO, logsourceLabel, tacticKo } from '../lib/labels';
import { CveChip, LevelBadge, Loading, StatusBadge, TacticChip } from '../components/ui';
import { ISSUE_URL, NOTICE } from '../lib/notices';
import { Queries } from '../components/Queries';
import ko from '../../content/ko.json';
import type { Attack, CveMap, KoNote, Rule } from '../types';

const KO = ko as Record<string, KoNote>;

export function RuleDetail({ id }: { id: string }) {
  const { data: r, error } = useData<Rule>(`rules/${id}.json`);
  const attack = useData<Attack>('attack.json').data;
  const cves = useData<CveMap>('cves.json').data;

  useEffect(() => {
    if (r) document.title = `${r.title} — Sigma 탐지 룰 | Sprout Security Detection Hub`;
  }, [r]);

  if (error) return <p className="empty">이 룰을 찾을 수 없습니다. 삭제됐거나 ID가 다를 수 있습니다. <Link to="/rules">룰 목록으로</Link></p>;
  if (!r) return <Loading />;

  const note = KO[r.id];
  const techName = (t: string) => attack?.techniques[t]?.name ?? '';
  const issue = `${ISSUE_URL}?title=${encodeURIComponent(`[오류 제보] ${r.title}`)}&body=${encodeURIComponent(`룰 ID: ${r.id}\n주소: ${location.href}\n\n어떤 부분이 잘못됐나요?\n`)}`;

  return (
    <article className="detail">
      <p className="crumb"><Link to="/rules">룰 카탈로그</Link> › {KIND_KO[r.kind] ?? r.kind}</p>
      <h1>{r.title}</h1>
      <div className="detail-badges">
        <LevelBadge level={r.level} />
        <StatusBadge status={r.status} />
        <span className="muted">{logsourceLabel(r.logsource.product, r.logsource.category, r.logsource.service)}</span>
      </div>

      <section className="card">
        <h2>
          한국어 해설 {note && <span className="badge ai" title="Claude가 원본 룰을 읽고 작성했습니다">AI 작성</span>}
        </h2>
        {note ? (
          <>
            <p className="lead-line">{note.summary}</p>
            <h3>무엇을 잡나</h3>
            <p>{note.what}</p>
            {note.analogy && (
              <p className="analogy"><strong>쉽게 말하면</strong> {note.analogy}</p>
            )}
            <h3>언제 오탐이 나나</h3>
            <p>{note.fp}</p>
            <h3>확인할 것</h3>
            <p>{note.check}</p>
          </>
        ) : (
          <>
            <p>{autoSummary(r, techName)}</p>
            <p className="muted">이 룰의 한국어 해설은 아직 준비 중입니다. 위 문장은 룰의 메타데이터로 자동으로 만든 요약이며, 아래 영문 설명이 원본입니다.</p>
            {r.description && (
              <blockquote lang="en" className="orig">
                <small>원본 설명(영문)</small>
                {r.description}
              </blockquote>
            )}
          </>
        )}
        <p className="muted small">
          원본 룰이 기준입니다. <a href={r.source_url} target="_blank" rel="noreferrer">SigmaHQ 원본 보기 ↗</a> · <a href={issue} target="_blank" rel="noreferrer">해설 오류 제보</a>
        </p>
      </section>

      <section className="card">
        <h2>상태와 오탐(원본 룰 기준)</h2>
        <p><StatusBadge status={r.status} /> {STATUS[r.status]?.note}</p>
        <h3>falsepositives</h3>
        {r.falsepositives.length ? (
          <ul>{r.falsepositives.map((x) => <li key={x}>{x}</li>)}</ul>
        ) : (
          <p className="muted">원본 룰에 적힌 오탐 사례가 없습니다. 오탐이 없다는 뜻이 아닙니다.</p>
        )}
        {note && r.description && (
          <blockquote lang="en" className="orig">
            <small>원본 설명(영문)</small>
            {r.description}
          </blockquote>
        )}
      </section>

      <section className="card">
        <h2>MITRE ATT&amp;CK® · CVE</h2>
        <dl className="kv">
          <dt>전술</dt>
          <dd>{r.tactics.length ? r.tactics.map((t) => <TacticChip key={t} t={t} />) : <span className="muted">없음</span>}</dd>
          <dt>기법</dt>
          <dd>
            {r.techniques.length ? (
              <ul className="plain">
                {r.techniques.map((t) => (
                  <li key={t}><Link to={`/rules?tech=${t}`} className="chip chip-soft">{t}</Link> {techName(t)}</li>
                ))}
              </ul>
            ) : (
              <span className="muted">없음</span>
            )}
          </dd>
          <dt>CVE</dt>
          <dd>
            {r.cves.length ? r.cves.map((c) => <CveChip key={c} id={c} kev={Boolean(cves?.[c]?.kev)} />) : <span className="muted">원본 룰의 태그·제목·설명·참고 링크에서 찾지 못했습니다.</span>}
          </dd>
        </dl>
        <p className="muted small">● 표시는 CISA KEV에 올라 실제 악용이 확인된 CVE입니다. ATT&CK는 가능한 모든 행동을 담지 않으므로 연결된 기법이 없거나 적다고 해서 위험이 낮다는 뜻은 아닙니다.</p>
      </section>

      <section className="card">
        <h2>내 SIEM 쿼리로 변환</h2>
        <Queries r={r} />
      </section>

      <section className="card">
        <h2>룰 본문 (Sigma YAML)</h2>
        <pre className="code" lang="yaml"><code>{r.raw}</code></pre>
      </section>

      <section className="card license">
        <h2>출처와 라이선스</h2>
        <dl className="kv">
          <dt>작성자</dt><dd>{r.author || '미표기'}</dd>
          <dt>룰 ID</dt><dd><code>{r.id}</code></dd>
          <dt>작성·수정</dt><dd>{fmtDate(r.date)} · {fmtDate(r.modified)}</dd>
          <dt>원본 룰</dt><dd><a href={r.source_url} target="_blank" rel="noreferrer">{r.path}</a></dd>
          <dt>라이선스</dt><dd>Detection Rule License (DRL) {r.license.replace('DRL ', '')} · <a href={NOTICE.drlUrl} target="_blank" rel="noreferrer">라이선스 전문</a></dd>
        </dl>
        {r.references.length > 0 && (
          <>
            <h3>참고 링크 (원본 룰)</h3>
            <ul className="refs">
              {r.references.map((u) => (
                <li key={u}>{/^https?:\/\//.test(u) ? <a href={u} target="_blank" rel="noreferrer noopener">{u}</a> : u}</li>
              ))}
            </ul>
          </>
        )}
        <p className="muted small">전술 이름: {r.tactics.map((t) => `${tacticKo(t)}(${t})`).join(', ') || '-'}</p>
      </section>
    </article>
  );
}
