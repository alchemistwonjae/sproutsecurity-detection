import { useMemo } from 'react';
import { Link } from '../lib/router';
import { useData } from '../lib/data';
import { Loading, PageHead } from '../components/ui';
import type { CveMap, RuleSlim } from '../types';

interface Item {
  no: string;
  name: string;
  why: string;
  evidence: string;
  link: string;
  label: string;
  match: (r: RuleSlim, kev: Set<string>) => boolean;
}

const ITEMS: Item[] = [
  {
    no: '2.11.3', name: '이상행위 분석 및 모니터링',
    why: '침해 시도를 수집한 로그에서 탐지하고 사후 조치하는 항목입니다. 탐지 룰 운영이 가장 직접 닿는 곳입니다.',
    evidence: '적용 중인 탐지 룰 목록과 버전, 경보 발생·조치 이력, 룰 튜닝(오탐 제외) 기록',
    link: '/rules?level=high,critical', label: '심각도 높음·치명 룰',
    match: (r) => r.l === 'high' || r.l === 'critical',
  },
  {
    no: '2.9.4 · 2.9.5', name: '로그 및 접속기록 관리·점검',
    why: '룰이 동작하려면 먼저 로그가 모여야 합니다. 어떤 로그를 수집하는지가 탐지 범위를 정합니다.',
    evidence: '로그 수집 대상·보관 기간 현황, 정기 점검 결과, 룰이 사용하는 로그 소스 목록(내 로그 기준 탐지 범위는 커버리지 지도에서 확인)',
    link: '/rules?product=windows,linux', label: 'Windows·Linux 로그 대상 룰',
    match: (r) => r.p === 'windows' || r.p === 'linux',
  },
  {
    no: '2.10.9', name: '악성코드 통제',
    why: '랜섬웨어 등 악성코드의 예방·탐지·대응 보호대책을 요구합니다. 영향(Impact) 단계의 룰이 관련됩니다.',
    evidence: '랜섬웨어 전조(섀도 복사본 삭제, 복구 기능 비활성화 등) 탐지 룰 적용 현황과 모의 점검 결과',
    link: '/rules?tactic=impact', label: '영향(Impact) 전술 룰',
    match: (r) => r.tc.includes('impact'),
  },
  {
    no: '2.11.2 · 2.10.8', name: '취약점 점검 및 조치 · 패치관리',
    why: '최신 취약점을 파악해 영향을 분석하고 조치하라는 항목입니다. 실제 악용(KEV) CVE와 대응 룰 유무가 참고가 됩니다.',
    evidence: 'KEV 등재 취약점의 자산 해당 여부 점검 결과, 패치 불가 시 보완 대책(탐지 룰 적용) 기록',
    link: '/rules?kev=1', label: '실제 악용 CVE가 연결된 룰',
    match: (r, kev) => r.c.some((c) => kev.has(c)),
  },
  {
    no: '2.5.3 · 2.5.5', name: '사용자 인증 · 특수 계정 및 권한 관리',
    why: '계정 탈취와 권한 상승은 침해의 흔한 경로입니다. 자격 증명 접근 전술의 룰이 관련됩니다.',
    evidence: '관리자 계정 변경·인증 이상 탐지 룰 적용 현황, 경보 조치 이력',
    link: '/rules?tactic=credential-access', label: '자격 증명 접근 전술 룰',
    match: (r) => r.tc.includes('credential-access'),
  },
  {
    no: '2.6.6', name: '원격접근 통제',
    why: '원격 접속 경로가 침투와 내부 이동의 통로가 됩니다. 횡이동 전술의 룰이 관련됩니다.',
    evidence: '원격 접속 장비(VPN 등) 로그 수집 여부, 횡이동 탐지 룰 적용 현황',
    link: '/rules?tactic=lateral-movement', label: '횡이동 전술 룰',
    match: (r) => r.tc.includes('lateral-movement'),
  },
  {
    no: '2.10.3', name: '공개서버 보안',
    why: '인터넷에 공개된 서버는 웹 공격의 대상입니다. 웹서버 로그를 대상으로 하는 룰이 관련됩니다.',
    evidence: '웹서버 접근 로그 수집 현황, 웹 공격(경로 조작 등) 탐지 룰 적용 현황',
    link: '/rules?cat=webserver', label: '웹서버 로그 대상 룰',
    match: (r) => r.cat === 'webserver',
  },
  {
    no: '2.10.2', name: '클라우드 보안',
    why: '클라우드 관리 로그(AWS·Azure·GCP)와 SaaS 로그를 대상으로 하는 룰이 관련됩니다.',
    evidence: '클라우드 감사 로그 수집 설정, 관리 콘솔·권한 변경 탐지 룰 적용 현황',
    link: '/rules?product=aws,azure,gcp,m365,okta', label: '클라우드·SaaS 룰',
    match: (r) => ['aws', 'azure', 'gcp', 'm365', 'okta'].includes(r.p),
  },
];

export function Isms() {
  const idx = useData<RuleSlim[]>('rules-index.json');
  const cves = useData<CveMap>('cves.json');
  const kev = useMemo(() => new Set(Object.entries(cves.data ?? {}).filter(([, v]) => v.kev).map(([k]) => k)), [cves.data]);
  const counts = useMemo(() => ITEMS.map((it) => (idx.data ?? []).filter((r) => it.match(r, kev)).length), [idx.data, kev]);
  if (!idx.data || !cves.data) return <Loading error={idx.error || cves.error} />;

  return (
    <>
      <PageHead
        title="ISMS-P 항목과 탐지 룰 연결"
        lead="인증 준비 중 ‘이 항목은 어떤 탐지 룰·로그와 닿고, 증적으로 무엇을 남기면 좋은가’를 찾아볼 수 있게 묶었습니다."
      />
      <p className="notice">
        편집 의견에 따른 참고용 연결입니다. 인증 심사 기준이나 요건이 아니며, 룰이 있다고 항목이 충족되는 것도 아닙니다. 항목 번호와 이름은 공개된 ISMS-P 인증기준 해설을 기준으로 적었으니, 실제 준비에는 최신 인증기준 고시와 심사 안내를 확인하세요.
      </p>
      <div className="isms">
        {ITEMS.map((it, i) => (
          <article key={it.no} className="card">
            <div className="card-head">
              <h2><span className="isms-no">{it.no}</span> {it.name}</h2>
              <Link to={it.link}>{it.label} ({counts[i].toLocaleString()}개) →</Link>
            </div>
            <p>{it.why}</p>
            <p className="evid"><strong>증적으로 남길 것</strong> {it.evidence}</p>
          </article>
        ))}
      </div>
      <p className="muted small">
        항목 번호 참고: <a href="https://itwiki.kr/w/ISMS-P_인증_기준_세부_점검_항목" target="_blank" rel="noreferrer">IT 위키 ISMS-P 인증 기준 세부 점검 항목</a>
      </p>
    </>
  );
}
