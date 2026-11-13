// 빌드 후 실행: 룰·CVE 페이지마다 제목/설명/canonical이 들어간 HTML을 만들고 sitemap.xml, robots.txt를 생성합니다.
// 검색 엔진이 JS 실행 없이도 각 주소의 내용을 읽을 수 있게 하는 것이 목적입니다.
import { readFileSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const DIST = join(ROOT, 'dist');
const SITE = 'https://detection.sproutsecurity.app';
const BRAND = 'Sprout Security Detection Hub';
const LEVEL = { critical: '치명', high: '높음', medium: '보통', low: '낮음', informational: '참고' };

const tpl = readFileSync(join(DIST, 'index.html'), 'utf8');
const json = (p) => JSON.parse(readFileSync(join(DIST, 'data', p), 'utf8'));
const ko = JSON.parse(readFileSync(join(ROOT, 'content', 'ko.json'), 'utf8'));
const idx = json('rules-index.json');
const cves = json('cves.json');
const meta = json('meta.json');

const esc = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const clip = (s, n) => {
  const t = String(s ?? '').replace(/\s+/g, ' ').trim();
  return t.length > n ? t.slice(0, n - 1) + '…' : t;
};

function page({ path, title, desc, body, ld }) {
  const url = SITE + path;
  let h = tpl;
  h = h.replace(/<title>[\s\S]*?<\/title>/, `<title>${esc(title)}</title>`);
  h = h.replace(/<meta name="description"[^>]*>/, `<meta name="description" content="${esc(desc)}" />`);
  h = h.replace(/<link rel="canonical"[^>]*>/, `<link rel="canonical" href="${url}" />`);
  const og = [
    ['og:type', 'website'], ['og:site_name', BRAND], ['og:locale', 'ko_KR'],
    ['og:title', title], ['og:description', desc], ['og:url', url],
  ].map(([k, v]) => `<meta property="${k}" content="${esc(v)}" />`).join('\n    ');
  const extra = `${og}\n    <meta name="twitter:card" content="summary" />` +
    (ld ? `\n    <script type="application/ld+json">${JSON.stringify(ld).replace(/</g, '\\u003c')}</script>` : '');
  h = h.replace('</head>', `    ${extra}\n  </head>`);
  h = h.replace('<div id="root"></div>', `<div id="root">${body}</div>`);
  return h;
}

const write = (path, html) => {
  const dir = path === '/' ? DIST : join(DIST, path);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'index.html'), html);
};

const urls = [];
const add = (path, lastmod) => urls.push({ path, lastmod });

// 1) 고정 페이지
const STATIC = [
  ['/', `${BRAND} — Sigma 탐지 룰 한국어 해설`, 'SigmaHQ 공개 탐지 룰을 한국어로 풀어 설명하고 MITRE ATT&CK®·CVE·실제 악용(KEV) 정보와 연결해 보여 주는 비공식 탐지 룰 허브.'],
  ['/rules', `룰 카탈로그 — ${BRAND}`, `SigmaHQ 공개 탐지 룰 ${idx.length.toLocaleString()}개를 심각도·MITRE ATT&CK®·로그 소스·CVE로 걸러 보고 Splunk·Elastic·KQL 쿼리로 변환해 봅니다.`],
  ['/coverage', `커버리지 지도 — ${BRAND}`, 'MITRE ATT&CK® 전술·기법별로 공개 Sigma 탐지 룰이 얼마나 있는지 한눈에 보는 지도.'],
  ['/weekly', `주간 신규 룰 — ${BRAND}`, '최근 8주 동안 SigmaHQ에 새로 추가되거나 바뀐 탐지 룰을 주 단위로 모아 봅니다.'],
  ['/gaps', `탐지 공백(KEV) — ${BRAND}`, '실제 악용이 확인된 CISA KEV 취약점 중 공개 Sigma 룰이 없는 것을 제조사별로 정리했습니다.'],
  ['/drafts', `룰 초안 — ${BRAND}`, '탐지 공백을 메우기 위한 한국어 설명이 붙은 Sigma 룰 초안(검증 전).'],
  ['/isms-p', `ISMS-P 연결 — ${BRAND}`, 'ISMS-P 인증기준 항목과 관련된 Sigma 탐지 룰을 연결해 보여 줍니다.'],
  ['/about', `소개·출처 — ${BRAND}`, '데이터 출처(SigmaHQ, MITRE ATT&CK®, CISA KEV, NVD)와 라이선스, 이 사이트의 한계를 안내합니다.'],
];
for (const [path, title, desc] of STATIC) {
  const ld = path === '/' ? {
    '@context': 'https://schema.org', '@type': 'WebSite', name: BRAND, url: SITE + '/', inLanguage: 'ko',
    potentialAction: { '@type': 'SearchAction', target: `${SITE}/rules?q={search_term_string}`, 'query-input': 'required name=search_term_string' },
  } : null;
  const body = `<main><h1>${esc(title.split(' — ')[0])}</h1><p>${esc(desc)}</p><p><a href="/rules">룰 카탈로그</a> · <a href="/coverage">커버리지 지도</a> · <a href="/weekly">주간 신규 룰</a></p></main>`;
  write(path, page({ path, title, desc, body, ld }));
  add(path, meta.builtAt?.slice(0, 10));
}

// 2) 룰 페이지
let nRule = 0;
for (const f of readdirSync(join(DIST, 'data', 'rules'))) {
  const r = json(`rules/${f}`);
  const note = ko[r.id];
  const lv = LEVEL[r.level] ?? r.level;
  const title = `${r.title} — Sigma 탐지 룰 | ${BRAND}`;
  const desc = clip(note?.summary ? `${note.summary} (심각도 ${lv})` : `심각도 ${lv} Sigma 탐지 룰. ${r.description}`, 160);
  const path = `/rules/${r.id}`;
  const body = `<main><article><h1>${esc(r.title)}</h1><p>${esc(desc)}</p>` +
    (r.cves?.length ? `<p>관련 CVE: ${r.cves.map((c) => `<a href="/cves/${c}">${c}</a>`).join(', ')}</p>` : '') +
    `<p>작성자: ${esc(r.author)} · 원본 라이선스: ${esc(r.license)} · <a href="${esc(r.source_url)}">SigmaHQ 원본</a></p></article></main>`;
  const ld = { '@context': 'https://schema.org', '@type': 'TechArticle', headline: r.title, description: desc, inLanguage: 'ko', url: SITE + path, dateModified: r.modified || r.date, author: { '@type': 'Person', name: r.author } };
  write(path, page({ path, title, desc, body, ld }));
  add(path, r.modified || r.date);
  nRule++;
}

// 3) CVE 페이지 (연결된 룰이 있는 것만: 내용 없는 얇은 페이지는 색인에서 제외)
let nCve = 0;
for (const [id, c] of Object.entries(cves)) {
  if (!c.rules.length) continue;
  const rs = c.rules.map((rid) => idx.find((x) => x.id === rid)).filter(Boolean);
  const title = `${id} 탐지 룰 ${rs.length}개 — ${BRAND}`;
  const desc = clip(`${id}${c.kev ? '(실제 악용 확인, CISA KEV)' : ''}와 연결된 Sigma 탐지 룰 ${rs.length}개: ${rs.map((x) => x.t).join(', ')}`, 160);
  const path = `/cves/${id}`;
  const body = `<main><h1>${id}</h1><ul>${rs.map((x) => `<li><a href="/rules/${x.id}">${esc(x.t)}</a></li>`).join('')}</ul></main>`;
  write(path, page({ path, title, desc, body }));
  add(path, meta.builtAt?.slice(0, 10));
  nCve++;
}

// 4) sitemap.xml, robots.txt
const xml = `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
  urls.map((u) => `  <url><loc>${SITE}${u.path === '/' ? '/' : u.path}</loc>${u.lastmod ? `<lastmod>${u.lastmod}</lastmod>` : ''}</url>`).join('\n') + '\n</urlset>\n';
writeFileSync(join(DIST, 'sitemap.xml'), xml);
writeFileSync(join(DIST, 'robots.txt'), `User-agent: *\nAllow: /\nDisallow: /data/\n\nSitemap: ${SITE}/sitemap.xml\n`);
console.log(`prerender: 고정 ${STATIC.length}, 룰 ${nRule}, CVE ${nCve}, sitemap ${urls.length}개`);
