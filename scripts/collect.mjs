// 수집 파이프라인: SigmaHQ 룰 + CISA KEV + MITRE ATT&CK (+ 선택: NVD) -> public/data/*.json
// 소스는 이 스크립트가 실행될 때(빌드 시점)만 호출하고, 사이트는 만들어 둔 JSON만 읽습니다.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { parse } from 'yaml';

const ROOT = new URL('..', import.meta.url).pathname;
const CACHE = join(ROOT, '.cache');
const SIGMA = join(CACHE, 'sigma');
const OUT = join(ROOT, 'public', 'data');
const NVD_KEY = process.env.NVD_API_KEY || '';

const KEV_URL = 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json';
const ATTACK_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';
const SIGMA_REPO = 'https://github.com/SigmaHQ/sigma';
const SIGMA_BLOB = 'https://github.com/SigmaHQ/sigma/blob/master/';

// 수집 대상 폴더(placeholder·deprecated·unsupported는 제외)
const DIRS = {
  rules: 'core',
  'rules-emerging-threats': 'emerging',
  'rules-threat-hunting': 'hunting',
  'rules-compliance': 'compliance',
  'rules-dfir': 'dfir',
};

mkdirSync(CACHE, { recursive: true });
rmSync(OUT, { recursive: true, force: true });
mkdirSync(join(OUT, 'rules'), { recursive: true });

const git = (...a) => execFileSync('git', a, { stdio: ['ignore', 'pipe', 'inherit'] }).toString().trim();
const log = (...a) => console.log('[collect]', ...a);
// 프록시 환경에서도 동작하도록 내려받기는 curl을 씁니다.
const getJson = (url, headers = []) =>
  JSON.parse(
    execFileSync('curl', ['-fsSL', '--max-time', '120', ...headers.flatMap((h) => ['-H', h]), url], {
      maxBuffer: 256 * 1024 * 1024,
    }).toString(),
  );

// 1) Sigma 저장소
if (existsSync(SIGMA)) {
  log('sigma: 업데이트');
  execFileSync('git', ['-C', SIGMA, 'fetch', '--depth', '1', 'origin'], { stdio: 'inherit' });
  execFileSync('git', ['-C', SIGMA, 'reset', '--hard', 'FETCH_HEAD'], { stdio: 'inherit' });
} else {
  log('sigma: clone');
  execFileSync('git', ['clone', '--depth', '1', SIGMA_REPO, SIGMA], { stdio: 'inherit' });
}
const sigmaCommit = git('-C', SIGMA, 'log', '-1', '--format=%H');
const sigmaCommitDate = git('-C', SIGMA, 'log', '-1', '--format=%cs');

const walk = (dir) =>
  readdirSync(dir).flatMap((n) => {
    const p = join(dir, n);
    return statSync(p).isDirectory() ? walk(p) : p.endsWith('.yml') ? [p] : [];
  });

// 2) ATT&CK
log('attack: 다운로드');
const attackRaw = getJson(ATTACK_URL);
const objs = attackRaw.objects.filter((o) => !o.revoked && !o.x_mitre_deprecated);
const tactics = objs
  .filter((o) => o.type === 'x-mitre-tactic')
  .map((o) => ({ short: o.x_mitre_shortname, name: o.name, id: o.external_references?.[0]?.external_id }));
const techniques = {};
for (const o of objs.filter((o) => o.type === 'attack-pattern')) {
  const id = o.external_references?.find((r) => r.source_name === 'mitre-attack')?.external_id;
  if (!id) continue;
  techniques[id] = { name: o.name, tactics: (o.kill_chain_phases ?? []).map((k) => k.phase_name) };
}
const attackVersion = attackRaw.objects.find((o) => o.type === 'x-mitre-collection')?.x_mitre_version ?? '';
log(`attack: tactics ${tactics.length}, techniques ${Object.keys(techniques).length}, v${attackVersion}`);

// 3) 룰 파싱
const CVE_RE = /CVE-\d{4}-\d{4,}/gi;
const asList = (v) => (v == null ? [] : Array.isArray(v) ? v.map(String) : [String(v)]);
const rules = [];
let skipped = 0;
for (const [dir, kind] of Object.entries(DIRS)) {
  const base = join(SIGMA, dir);
  if (!existsSync(base)) continue;
  for (const file of walk(base)) {
    const text = readFileSync(file, 'utf8');
    let y;
    try {
      y = parse(text);
    } catch {
      skipped++;
      continue;
    }
    if (!y || !y.id || !y.title) {
      skipped++;
      continue;
    }
    // 룰 파일에 DRL이 아닌 별도 라이선스 표기가 있으면 수집하지 않는다
    if (y.license && !/DRL|Detection Rule License/i.test(String(y.license))) {
      skipped++;
      log('라이선스 별도 표기로 제외:', y.title, y.license);
      continue;
    }
    const tags = asList(y.tags);
    const tacticSet = new Set();
    const techSet = new Set();
    for (const t of tags) {
      const m = /^attack\.(t\d{4}(?:\.\d{3})?)$/i.exec(t);
      if (m) techSet.add(m[1].toUpperCase());
      else if (/^attack\.[a-z-]+$/.test(t)) tacticSet.add(t.slice(7));
    }
    const hay = [y.title, y.description ?? '', ...tags, ...asList(y.references)].join(' ');
    const cves = [...new Set((hay.match(CVE_RE) ?? []).map((c) => c.toUpperCase()))].sort();
    const rel = relative(SIGMA, file);
    const ls = y.logsource ?? {};
    rules.push({
      id: String(y.id),
      title: String(y.title),
      status: y.status ? String(y.status) : 'unknown',
      level: y.level ? String(y.level).split('#')[0].trim() : 'unknown',
      date: y.date ? String(y.date).slice(0, 10).replace(/\//g, '-') : '',
      modified: y.modified ? String(y.modified).slice(0, 10).replace(/\//g, '-') : '',
      author: y.author ? String(y.author) : '',
      description: y.description ? String(y.description).trim() : '',
      references: asList(y.references),
      falsepositives: asList(y.falsepositives),
      tags,
      tactics: [...tacticSet],
      techniques: [...techSet].sort(),
      cves,
      logsource: { product: ls.product ?? '', category: ls.category ?? '', service: ls.service ?? '' },
      kind,
      path: rel,
      source_url: SIGMA_BLOB + rel,
      license: 'DRL 1.1',
      raw: text,
    });
  }
}
log(`sigma: 룰 ${rules.length}개 (건너뜀 ${skipped}) @ ${sigmaCommit.slice(0, 7)}`);

// 4) KEV
log('kev: 다운로드');
const kevRaw = getJson(KEV_URL);
const kev = {};
for (const v of kevRaw.vulnerabilities) {
  kev[v.cveID] = {
    name: v.vulnerabilityName,
    vendor: v.vendorProject,
    product: v.product,
    added: v.dateAdded,
    due: v.dueDate,
    ransomware: v.knownRansomwareCampaignUse === 'Known',
    desc: v.shortDescription,
  };
}
log(`kev: ${Object.keys(kev).length}건 (catalog ${kevRaw.catalogVersion})`);

// 5) CVE 맵 (룰이 참조하는 CVE + KEV 전체)
const cveRules = {};
for (const r of rules) for (const c of r.cves) (cveRules[c] ??= []).push(r.id);
const allCves = new Set([...Object.keys(cveRules), ...Object.keys(kev)]);
const cves = {};
for (const id of [...allCves].sort()) {
  cves[id] = { rules: cveRules[id] ?? [], ...(kev[id] ? { kev: kev[id] } : {}) };
}

// 6) NVD (선택): 키가 있을 때만, 룰이 참조하는 CVE + KEV만
let nvdCount = 0;
if (NVD_KEY) {
  const targets = Object.keys(cves).filter((c) => cves[c].rules.length || cves[c].kev);
  log(`nvd: ${targets.length}건 조회 (키 사용, 30초 50회 이내로 조절)`);
  for (let i = 0; i < targets.length; i++) {
    const id = targets[i];
    try {
      {
        const c = getJson(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${id}`, [`apiKey: ${NVD_KEY}`]).vulnerabilities?.[0]?.cve;
        const m = c?.metrics?.cvssMetricV31?.[0] ?? c?.metrics?.cvssMetricV40?.[0] ?? c?.metrics?.cvssMetricV30?.[0];
        if (c) {
          cves[id].nvd = {
            published: c.published?.slice(0, 10),
            desc: c.descriptions?.find((d) => d.lang === 'en')?.value ?? '',
            score: m?.cvssData?.baseScore ?? null,
            severity: m?.cvssData?.baseSeverity ?? null,
            enriched: Boolean(m),
          };
          nvdCount++;
        }
      }
    } catch {
      /* 이번 실행에서는 건너뜀 */
    }
    await new Promise((r) => setTimeout(r, 700));
  }
  log(`nvd: ${nvdCount}건 보강`);
} else {
  log('nvd: NVD_API_KEY 없음 — 건너뜀 (KEV 정보만 표시)');
}

// 7) 주간 신규 룰 (룰의 date 기준, 최근 8주)
const monday = (d) => {
  const x = new Date(d + 'T00:00:00Z');
  const day = (x.getUTCDay() + 6) % 7;
  x.setUTCDate(x.getUTCDate() - day);
  return x.toISOString().slice(0, 10);
};
const newest = rules.reduce((m, r) => (r.date > m ? r.date : m), '');
const weekly = {};
for (const r of rules) {
  if (!r.date) continue;
  const w = monday(r.date);
  (weekly[w] ??= { week: w, added: [], modified: [] }).added.push(r.id);
}
for (const r of rules) {
  if (!r.modified || r.modified === r.date) continue;
  const w = monday(r.modified);
  (weekly[w] ??= { week: w, added: [], modified: [] }).modified.push(r.id);
}
const weeks = Object.values(weekly)
  .sort((a, b) => (a.week < b.week ? 1 : -1))
  .filter((w) => w.week <= newest)
  .slice(0, 8);

// 8) 출력
const slim = rules.map((r) => ({
  id: r.id, t: r.title, s: r.status, l: r.level, d: r.date, m: r.modified, a: r.author,
  k: r.techniques, tc: r.tactics, c: r.cves, kind: r.kind,
  p: r.logsource.product, cat: r.logsource.category, sv: r.logsource.service,
}));
slim.sort((a, b) => (a.d < b.d ? 1 : a.d > b.d ? -1 : a.t.localeCompare(b.t)));
for (const r of rules) writeFileSync(join(OUT, 'rules', `${r.id}.json`), JSON.stringify(r));
const w = (n, o) => writeFileSync(join(OUT, n), JSON.stringify(o));
w('rules-index.json', slim);
w('cves.json', cves);
w('attack.json', { version: attackVersion, tactics, techniques });
w('weekly.json', weeks);
w('meta.json', {
  builtAt: new Date().toISOString(),
  sigma: { commit: sigmaCommit, date: sigmaCommitDate, rules: rules.length },
  kev: { catalogVersion: kevRaw.catalogVersion, dateReleased: kevRaw.dateReleased, count: Object.keys(kev).length },
  attack: { version: attackVersion },
  nvd: { enriched: nvdCount },
});
log('완료 →', OUT);
