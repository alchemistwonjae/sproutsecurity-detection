import { useState } from 'react';
import type { Rule } from '../types';
import { NOTICE } from '../lib/notices';

export function Queries({ r }: { r: Rule }) {
  const qs = r.queries ?? [];
  const [i, setI] = useState(0);
  const [done, setDone] = useState(false);
  if (!qs.length) {
    return <p className="muted">이 룰은 자동 변환 결과가 없습니다(지원하지 않는 로그 종류이거나 변환 도구가 처리하지 못한 경우). 원본 YAML을 직접 변환해 보세요.</p>;
  }
  const q = qs[Math.min(i, qs.length - 1)];
  const copy = async () => {
    const header = `# ${r.title}\n# 원본 룰: ${r.source_url}\n# 작성자: ${r.author} · Detection Rule License (DRL) 1.1\n# 자동 변환 — 필드 이름과 로그 소스는 환경에 맞게 조정하세요.\n`;
    try {
      await navigator.clipboard.writeText(header + q.query);
      setDone(true);
      setTimeout(() => setDone(false), 1600);
    } catch {
      /* 복사 권한이 없으면 직접 선택해서 복사 */
    }
  };
  return (
    <>
      <div className="tabs" role="tablist" aria-label="SIEM 종류">
        {qs.map((x, k) => (
          <button key={x.id} type="button" role="tab" aria-selected={k === i} className={k === i ? 'on' : ''} onClick={() => setI(k)}>
            {x.label}
          </button>
        ))}
        <button type="button" className="copy" onClick={copy}>{done ? '복사됨 ✓' : '복사(출처 주석 포함)'}</button>
      </div>
      <pre className="code" lang="text"><code>{q.query}</code></pre>
      <p className="muted small">
        룰 작성자: {r.author || '미표기'} · <a href={NOTICE.drlUrl} target="_blank" rel="noreferrer">DRL 1.1</a> · <a href={r.source_url} target="_blank" rel="noreferrer">원본 룰</a>
      </p>
      <p className="notice">
        pySigma로 자동 변환한 결과이며 내 환경의 필드 이름·인덱스·로그 수집 방식과 다를 수 있습니다. 운영에 넣기 전에 샘플 로그로 확인하고 오탐을 점검하세요. 변환이 정확하다고 보장하지 않습니다.
      </p>
    </>
  );
}
