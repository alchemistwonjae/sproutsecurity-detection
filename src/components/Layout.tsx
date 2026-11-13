import { useEffect, useState, type ReactNode } from 'react';
import { Link } from '../lib/router';
import { SearchBox } from './SearchBox';
import { applyTheme, readTheme, type Theme } from '../theme';
import { NOTICE, ISSUE_URL, PORTAL_URL } from '../lib/notices';
import { useData } from '../lib/data';
import type { Meta } from '../types';

const NAV = [
  { to: '/', label: '홈' },
  { to: '/rules', label: '룰 카탈로그' },
  { to: '/coverage', label: '커버리지 지도' },
  { to: '/weekly', label: '주간 신규 룰' },
  { to: '/gaps', label: '탐지 공백(KEV)' },
  { to: '/drafts', label: '룰 초안' },
  { to: '/isms-p', label: 'ISMS-P 연결' },
  { to: '/about', label: '소개·출처' },
];

export function Layout({ path, children }: { path: string; children: ReactNode }) {
  const mq = '(prefers-color-scheme: dark)';
  const [theme, setTheme] = useState<Theme>(readTheme);
  const [osDark, setOsDark] = useState(() => matchMedia(mq).matches);
  useEffect(() => {
    const m = matchMedia(mq);
    const on = () => setOsDark(m.matches);
    m.addEventListener('change', on);
    return () => m.removeEventListener('change', on);
  }, []);
  const dark = theme === 'auto' ? osDark : theme === 'dark';
  const flip = () => {
    const next: Theme = dark ? 'light' : 'dark';
    setTheme(next);
    applyTheme(next);
  };
  const { data: meta } = useData<Meta>('meta.json');

  return (
    <>
      <a className="skip" href="#main">본문으로 건너뛰기</a>
      <header className="gnb">
        <div className="wrap gnb-top">
          <Link to="/" className="brand">
            <svg className="brand-mark" viewBox="16 10 32 44" aria-hidden="true">
              <polygon className="lt" points="16,10 48,10 48,17 23,17 23,28.5 33.24,28.5 26.24,35.5 16,35.5" />
              <polygon className="lg" points="37.76,28.5 48,28.5 48,54 16,54 16,47 41,47 41,35.5 30.76,35.5" />
            </svg>
            <span className="brand-text">
              <small>Sprout Security 탐지 룰 허브</small>
              <strong>Detection Hub</strong>
            </span>
          </Link>
          <SearchBox variant="gnb" placeholder="룰 제목, CVE, ATT&CK 기법(예: T1003, CVE-2021-1675)" />
          <button type="button" className="icon-btn" onClick={flip} aria-label={dark ? '라이트 모드로 전환' : '다크 모드로 전환'} title={dark ? '라이트 모드' : '다크 모드'}>
            {dark ? '☀' : '☾'}
          </button>
        </div>
        <nav className="wrap nav" aria-label="주 메뉴">
          {NAV.map((n) => (
            <Link key={n.to} to={n.to} className={n.to === '/' ? (path === '/' ? 'on' : '') : path.startsWith(n.to) ? 'on' : ''} aria-current={n.to === path ? 'page' : undefined}>
              {n.label}
            </Link>
          ))}
          <a className="nav-out" href={PORTAL_URL}>오늘도 무사히(정보보호포털) ↗</a>
        </nav>
      </header>
      <main id="main" className="wrap">{children}</main>
      <footer className="foot">
        <div className="wrap foot-in">
          <p><strong>{NOTICE.unofficial}</strong></p>
          <ul>
            <li>
              {NOTICE.drl} <a href={NOTICE.drlUrl} target="_blank" rel="noreferrer">라이선스 보기</a>
            </li>
            <li>{NOTICE.nvd}</li>
            <li>
              MITRE ATT&amp;CK® 데이터를 사용합니다. {NOTICE.attack}{' '}
              <a href={NOTICE.attackUrl} target="_blank" rel="noreferrer">이용약관</a>
            </li>
            <li>
              {NOTICE.kev} <a href={NOTICE.kevUrl} target="_blank" rel="noreferrer">데이터 저장소</a>
            </li>
            <li>한국어 해설은 AI가 작성했으며, 원본 룰 링크와 함께 표시합니다. 오류는 <a href={ISSUE_URL} target="_blank" rel="noreferrer">GitHub 이슈</a>로 알려 주세요.</li>
          </ul>
          <p className="muted">
            운영: 스프라우트시큐리티
            {meta && ` · SigmaHQ ${meta.sigma.commit.slice(0, 7)}(${meta.sigma.date}) · KEV ${meta.kev.catalogVersion} · 빌드 ${meta.builtAt.slice(0, 10)}`}
          </p>
        </div>
      </footer>
    </>
  );
}
