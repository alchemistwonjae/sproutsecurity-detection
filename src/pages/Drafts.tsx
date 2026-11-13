import { PageHead } from '../components/ui';
import { Link } from '../lib/router';
import { ISSUE_URL, NOTICE } from '../lib/notices';
import { useData } from '../lib/data';
import type { CveMap } from '../types';
import drafts from '../../content/drafts.json';

interface Draft {
  id: string; product: string; cves: string[]; yaml: string;
  ko: { summary: string; what: string; analogy: string; fp: string; check: string };
}
const D = drafts as Draft[];

export function Drafts() {
  const cves = useData<CveMap>('cves.json').data;
  return (
    <>
      <PageHead
        title="룰 초안: 실제 악용 중인데 룰이 없는 취약점"
        lead="탐지 공백 중 공개된 공격 요청 패턴이 비교적 분명한 것부터 룰 초안을 만들었습니다. SigmaHQ에 기여하기 전 단계의 작업 노트입니다."
      />
      <p className="notice">
        <strong>검증 전 초안입니다.</strong> 공개된 공격 사례의 요청 패턴을 바탕으로 AI가 작성했고, 실제 로그나 PoC 트래픽으로 시험하지 않았으며 SigmaHQ에 제출하지 않았습니다. 운영 환경에 넣기 전에 벤더 권고문·재현 로그와 대조하고 오탐을 확인하세요. 제품을 고른 기준은 기업 환경에서 흔한 VPN·엣지 장비라는 점이며, 국내 점유율을 확인한 것은 아닙니다.
      </p>
      {D.map((d) => (
        <article key={d.id} className="card">
          <h2>
            {d.product} <span className="badge st-experimental">초안</span> <span className="badge ai">AI 작성</span>
          </h2>
          <p className="lead-line">{d.ko.summary}</p>
          <p>
            {d.cves.map((c) => (
              <Link key={c} to={`/cves/${c}`} className={`chip${cves?.[c]?.kev ? ' chip-kev' : ''}`}>{c}{cves?.[c]?.kev ? ' ●' : ''}</Link>
            ))}{' '}
            <span className="muted small">
              {d.cves.every((c) => cves?.[c] && cves[c].rules.length === 0) ? '현재 수집한 Sigma 룰에 이 CVE를 명시한 룰이 없습니다.' : ''}
            </span>
          </p>
          <h3>무엇을 잡나</h3>
          <p>{d.ko.what}</p>
          <p className="analogy"><strong>쉽게 말하면</strong> {d.ko.analogy}</p>
          <h3>언제 오탐이 나나</h3>
          <p>{d.ko.fp}</p>
          <h3>확인할 것</h3>
          <p>{d.ko.check}</p>
          <h3>Sigma YAML (초안)</h3>
          <pre className="code" lang="yaml"><code>{d.yaml}</code></pre>
        </article>
      ))}
      <section className="card">
        <h2>SigmaHQ에 기여하려면</h2>
        <ol>
          <li>샘플 로그나 재현 환경으로 룰이 실제로 걸리는지, 정상 요청에서 오탐이 없는지 확인합니다.</li>
          <li>SigmaHQ 저장소의 기여 안내와 룰 작성 규칙(필드 이름, 태그, 파일 위치)에 맞춰 고칩니다.</li>
          <li>Detection Rule License 1.1 아래 공개된다는 점({' '}
            <a href={NOTICE.drlUrl} target="_blank" rel="noreferrer">라이선스</a>)을 확인하고 풀 리퀘스트를 엽니다.</li>
        </ol>
        <p className="muted small">초안에 문제가 있으면 <a href={ISSUE_URL} target="_blank" rel="noreferrer">GitHub 이슈</a>로 알려 주세요.</p>
      </section>
    </>
  );
}
