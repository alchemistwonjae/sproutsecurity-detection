import { PageHead } from '../components/ui';
import { ISSUE_URL, NOTICE } from '../lib/notices';
import { useData } from '../lib/data';
import type { Meta } from '../types';

export function About() {
  const meta = useData<Meta>('meta.json').data;
  return (
    <>
      <PageHead title="소개와 데이터 출처" lead="Sprout Security Detection Hub는 SigmaHQ의 공개 탐지 룰을 한국어로 풀어 설명하고, MITRE ATT&CK®·CVE·실제 악용(KEV) 정보와 엮어 보여 주는 비공식 사이트입니다." />
      <section className="card">
        <h2>무엇을 하나</h2>
        <ul>
          <li>룰마다 ‘무엇을 잡고, 언제 오탐이 나는지’를 한국어로 설명합니다(해설이 있는 룰에는 ‘AI 작성’ 표시).</li>
          <li>룰 ↔ ATT&amp;CK 기법 ↔ CVE ↔ KEV를 한 화면에서 오가며 찾을 수 있습니다.</li>
          <li>실제 악용 중인데 Sigma 룰이 CVE를 명시하지 않은 취약점을 보여 탐지 공백을 드러냅니다.</li>
        </ul>
        <p className="muted">Sigma는 수법(행위)을 잡는 규칙이므로 IP·도메인 같은 지표(IoC)는 다루지 않습니다.</p>
      </section>
      <section className="card">
        <h2>데이터 출처</h2>
        <table className="tbl">
          <thead><tr><th>소스</th><th>용도</th><th>이용 조건</th></tr></thead>
          <tbody>
            <tr><td>SigmaHQ 룰</td><td>룰 본문·메타</td><td>Detection Rule License 1.1 — 작성자·원본 링크·라이선스 표기 유지</td></tr>
            <tr><td>MITRE ATT&amp;CK®</td><td>기법 분류·이름</td><td>MITRE 저작권 고지 유지</td></tr>
            <tr><td>NVD API</td><td>CVE 설명·점수(룰이 참조하는 CVE와 KEV만)</td><td>NVD 고지 문구 표시</td></tr>
            <tr><td>CISA KEV</td><td>실제 악용 CVE 목록</td><td>CC0 1.0</td></tr>
            <tr><td>AlienVault OTX</td><td>—</td><td>약관상 재게시·표시가 어려워 데이터를 쓰지 않고 링크 아웃만 합니다</td></tr>
          </tbody>
        </table>
        {meta && (
          <p className="muted small">
            현재 데이터: SigmaHQ 룰 {meta.sigma.rules.toLocaleString()}개(커밋 {meta.sigma.commit.slice(0, 7)}, {meta.sigma.date}) · KEV {meta.kev.count.toLocaleString()}건(카탈로그 {meta.kev.catalogVersion}) · NVD 보강 {meta.nvd.enriched.toLocaleString()}건 · 빌드 {meta.builtAt.slice(0, 16).replace('T', ' ')} UTC
          </p>
        )}
      </section>
      <section className="card">
        <h2>유의할 점</h2>
        <ul>
          <li>{NOTICE.unofficial}</li>
          <li>MITRE ATT&amp;CK®는 가능한 모든 기법을 담지 않으므로, 연결된 기법이 있다고 해서 완전한 방어를 뜻하지 않습니다.</li>
          <li>한국어 해설은 AI가 작성한 것으로 오류가 있을 수 있습니다. 판단은 항상 원본 룰을 기준으로 하세요.</li>
          <li>잘못된 내용은 <a href={ISSUE_URL} target="_blank" rel="noreferrer">GitHub 이슈</a>로 알려 주세요.</li>
        </ul>
      </section>
    </>
  );
}
