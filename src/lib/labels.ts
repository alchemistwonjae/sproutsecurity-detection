import type { Rule, RuleSlim } from '../types';

export const LEVEL: Record<string, { ko: string; rank: number }> = {
  critical: { ko: '치명', rank: 5 },
  high: { ko: '높음', rank: 4 },
  medium: { ko: '보통', rank: 3 },
  low: { ko: '낮음', rank: 2 },
  informational: { ko: '참고', rank: 1 },
  unknown: { ko: '미정', rank: 0 },
};
export const levelKo = (l: string) => LEVEL[l]?.ko ?? l;

export const STATUS: Record<string, { ko: string; note: string }> = {
  stable: { ko: '안정', note: '충분히 검증된 룰입니다. 그래도 환경에 따라 오탐이 날 수 있습니다.' },
  test: { ko: '테스트', note: '검증 중인 룰입니다. 적용 전에 내 환경에서 오탐을 확인하세요.' },
  experimental: { ko: '실험적', note: '아직 실험 단계입니다. 오탐이 많거나 탐지가 불완전할 수 있습니다.' },
  deprecated: { ko: '폐기 예정', note: '더 이상 권장되지 않는 룰입니다.' },
  unsupported: { ko: '미지원', note: '지원되지 않는 룰입니다.' },
  unknown: { ko: '미정', note: '원본 룰에 상태가 적혀 있지 않습니다.' },
};
export const statusKo = (s: string) => STATUS[s]?.ko ?? s;

// 공식 영문 이름은 ATT&CK 데이터의 것을 쓰고, 한국어는 이해를 돕는 표기입니다.
export const TACTIC_KO: Record<string, string> = {
  reconnaissance: '정찰',
  'resource-development': '자원 개발',
  'initial-access': '초기 침투',
  execution: '실행',
  persistence: '지속성',
  'privilege-escalation': '권한 상승',
  stealth: '은닉',
  'defense-impairment': '방어 무력화',
  'credential-access': '자격 증명 접근',
  discovery: '탐색',
  'lateral-movement': '횡이동',
  collection: '수집',
  'command-and-control': '명령·제어',
  exfiltration: '반출',
  impact: '영향',
};
export const tacticKo = (t: string) => TACTIC_KO[t] ?? t;

// CISA SSVC(Exploitation / Automatable / Technical Impact) 값의 한국어 표기. 모르는 값은 원문을 그대로 보여 준다.
export const SSVC_KO = {
  exploitation: { none: '악용 사례 없음', poc: '공개된 시연 코드(PoC) 있음', active: '실제 악용 중' },
  automatable: { yes: '자동화 공격 가능', no: '자동화 어려움' },
  impact: { partial: '일부 영향', total: '시스템 전체 장악 가능' },
} as const;
export const ssvcKo = (kind: keyof typeof SSVC_KO, v: string) =>
  (SSVC_KO[kind] as Record<string, string>)[v.toLowerCase()] ?? (v || '-');

export const KIND_KO: Record<string, string> = {
  core: '일반 탐지',
  emerging: '신규 위협·취약점',
  hunting: '위협 헌팅용',
  compliance: '컴플라이언스',
  dfir: '포렌식',
};

export const logsourceLabel = (p: string, cat: string, sv: string) => [p, cat || sv].filter(Boolean).join(' · ') || '미지정';

export const fmtDate = (d: string) => (d ? d.replace(/-/g, '.') : '-');

export function autoSummary(r: Pick<Rule, 'level' | 'status' | 'logsource' | 'techniques'>, techName: (t: string) => string) {
  const ls = logsourceLabel(r.logsource.product, r.logsource.category, r.logsource.service);
  const tech = r.techniques.length ? ` 연결된 MITRE ATT&CK® 기법은 ${r.techniques.map((t) => `${t} ${techName(t)}`).join(', ')}입니다.` : '';
  return `이 룰은 '${ls}' 로그를 대상으로 하며, 원본 룰이 정한 심각도는 '${levelKo(r.level)}', 상태는 '${statusKo(r.status)}'입니다.${tech}`;
}

export const slimHay = (r: RuleSlim) => `${r.t} ${r.id} ${r.a} ${r.c.join(' ')} ${r.k.join(' ')} ${r.p} ${r.cat} ${r.sv}`.toLowerCase();
