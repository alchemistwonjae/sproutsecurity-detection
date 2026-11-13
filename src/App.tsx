import { useEffect } from 'react';
import { Layout } from './components/Layout';
import { useLocation } from './lib/router';
import { Home } from './pages/Home';
import { Rules } from './pages/Rules';
import { RuleDetail } from './pages/RuleDetail';
import { CveDetail } from './pages/CveDetail';
import { Weekly } from './pages/Weekly';
import { Gaps } from './pages/Gaps';
import { About } from './pages/About';
import { Coverage } from './pages/Coverage';
import { Drafts } from './pages/Drafts';
import { Isms } from './pages/Isms';

const BASE = 'Sprout Security Detection Hub';

export default function App() {
  const { path, search } = useLocation();
  useEffect(() => {
    // 룰·CVE 상세는 각 페이지가 자기 제목을 정합니다
    if (/^\/(rules|cves)\/./.test(path)) return;
    const NAMES: Record<string, string> = { '/rules': '룰 카탈로그', '/coverage': '커버리지 지도', '/weekly': '주간 신규 룰', '/gaps': '탐지 공백(KEV)', '/drafts': '룰 초안', '/isms-p': 'ISMS-P 연결', '/about': '소개·출처' };
    document.title = NAMES[path] ? `${NAMES[path]} — ${BASE}` : `${BASE} — Sigma 탐지 룰 한국어 해설`;
  }, [path]);

  let page;
  let m: RegExpExecArray | null;
  if (path === '/') page = <Home />;
  else if (path === '/rules') page = <Rules search={search} />;
  else if ((m = /^\/rules\/([0-9a-f-]{36})$/i.exec(path))) page = <RuleDetail id={m[1].toLowerCase()} />;
  else if ((m = /^\/cves\/(CVE-\d{4}-\d{4,})$/i.exec(path))) page = <CveDetail id={m[1].toUpperCase()} />;
  else if (path === '/weekly') page = <Weekly />;
  else if (path === '/gaps') page = <Gaps search={search} />;
  else if (path === '/coverage') page = <Coverage />;
  else if (path === '/drafts') page = <Drafts />;
  else if (path === '/isms-p') page = <Isms />;
  else if (path === '/about') page = <About />;
  else page = <p className="empty">페이지를 찾을 수 없습니다.</p>;

  return <Layout path={path}>{page}</Layout>;
}
