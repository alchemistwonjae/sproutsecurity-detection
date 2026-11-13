# Sprout Security Detection Hub

SigmaHQ 공개 탐지 룰을 한국어로 풀어 설명하고 MITRE ATT&CK®·CVE·CISA KEV와 연결해 보여 주는 비공식 사이트.
도메인(예정): detection.sproutsecurity.app · 기획안: Claude Project "보안사고 사이트"의 `claude/detection-hub-plan.md`

## 로컬 실행

```bash
npm install
npm run collect     # Sigma·KEV·ATT&CK 수집 → public/data (처음 몇 분 걸릴 수 있음)
npm run dev         # http://localhost:5173
```

- `NVD_API_KEY` 환경변수를 주면 룰이 참조하는 CVE와 KEV만 NVD에서 보강합니다(키 없으면 건너뜀). 키는 브라우저에 넣지 않고 Actions 시크릿에만 둡니다.
- 사이트는 빌드 시점에 만든 `public/data/*.json`만 읽습니다.
- 한국어 해설은 `content/ko.json`(룰 ID → 해설)에 추가합니다. 없는 룰은 메타데이터 자동 요약 + 영문 원문을 보여 줍니다.
- 고지 문구는 `src/lib/notices.ts` 한 곳에서 관리합니다.

## SIEM 쿼리 변환 (선택)

룰 상세의 "내 SIEM 쿼리로 변환"은 빌드 시점에 pySigma로 만듭니다. 사이트에는 변환 도구가 들어가지 않습니다.

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
npm run collect && npm run convert
```

변환은 자동이라 필드 이름·로그 소스 매핑은 환경에 맞춰 조정해야 하며, 변환 결과에는 룰 작성자·DRL 1.1·원본 링크를 함께 표시합니다.

## 콘텐츠 파일

- `content/ko.json`: 룰 ID → 한국어 해설(AI 작성 표시)
- `content/drafts.json`: 검증 전 룰 초안(탐지 공백 대응). SigmaHQ에는 제출하지 않았습니다.
- ISMS-P 연결은 `src/pages/Isms.tsx`, 커버리지 지도는 `src/pages/Coverage.tsx`

## 배포 (Cloudflare Workers)

`npm run collect && npm run build` 후 `npx wrangler deploy`. `wrangler.jsonc`는 SPA 모드입니다.
