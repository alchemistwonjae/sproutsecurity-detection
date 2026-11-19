// 수집 파이프라인: SigmaHQ 룰 + CISA KEV + MITRE ATT&CK (+ 선택: NVD) -> public/data/*.json
// 소스는 이 스크립트가 실행될 때(빌드 시점)만 호출하고, 사이트는 만들어 둔 JSON만 읽습니다.
import { execFile, execFileSync } from 'node:child_process';
import { promisify } from 'node:util';
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
// CISA Vulnrichment(CC0): NVD가 비워 둔 점수·CWE·영향 제품을 CISA가 채운 CVE 기록. 경로는 <연도>/<번호÷1000>xxx/<CVE>.json
const VR_BASE = 'https://raw.githubusercontent.com/cisagov/vulnrichment/develop';
// Atomic Red Team(MIT): 기법별 테스트 목록. 데이터는 복사하지 않고 '테스트가 있는 기법 ID'만 가져와 링크 아웃에 씁니다.
const ART_INDEX = 'https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/Indexes-CSV/index.csv';
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

const execFileP = promisify(execFile);
// 404는 null(해당 파일 없음), 그 밖의 실패는 예외로 알립니다.
const getTextOrNull = async (url) => {
  try {
    return (await execFileP('curl', ['-fsSL', '--max-time', '60', '--retry', '2', url], { maxBuffer: 64 * 1024 * 1024 })).stdout;
  } catch (e) {
    if (e.code === 22) return null;
    throw e;
  }
};
const pool = async (items, size, fn) => {
  let i = 0;
  await Promise.all(
    Array.from({ length: size }, async () => {
      while (i < items.length) await fn(items[i++]);
    }),
  );
};

// 따옴표 안의 쉼표를 지키는 한 줄 CSV 분해(이름에 쉼표가 있는 기법·테스트가 있어 split(',')로는 칸이 밀립니다)
const csvLine = (line) => {
  const out = [];
  let cur = '';
  let q = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (q) {
      if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (ch === '"') q = false;
      else cur += ch;
    } else if (ch === '"') q = true;
    else if (ch === ',') { out.push(cur); cur = ''; }
    else cur += ch;
  }
  out.push(cur.replace(/\r$/, ''));
  return out;
};

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

// 2-1) Atomic Red Team: 테스트가 있는 기법 ID -> 테스트 수 (실패해도 빌드는 계속, 링크만 빠짐)
const atomics = {};
try {
  const csv = await getTextOrNull(ART_INDEX);
  if (!csv) throw new Error('index.csv 없음');
  const seen = new Set();
  for (const line of csv.split('\n').slice(1)) {
    const c = csvLine(line);
    const t = c[1];
    if (!/^T\d{4}(\.\d{3})?$/.test(t ?? '')) continue;
    const key = `${t}|${c[3]}`; // 한 테스트가 여러 전술에 걸려 중복 줄이 생기므로 (기법, 테스트 번호)로 센다
    if (seen.has(key)) continue;
    seen.add(key);
    atomics[t] = (atomics[t] ?? 0) + 1;
  }
  log(`atomics: 기법 ${Object.keys(atomics).length}개, 테스트 ${seen.size}개`);
} catch (e) {
  log('atomics: 가져오지 못해 건너뜀 —', e.message);
}

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

// 6-1) CISA Vulnrichment: 룰이 참조하는 CVE + KEV 전체. 키가 필요 없고 NVD처럼 호출 제한이 빡빡하지 않습니다.
// CISA ADP 컨테이너가 없는 CVE(보강 대상이 아닌 것)는 404라서 그냥 비워 둡니다.
const vrOf = (rec) => {
  const adp = (rec.containers?.adp ?? []).find((a) => a.providerMetadata?.shortName === 'CISA-ADP');
  if (!adp) return null;
  const out = {};
  const ms = adp.metrics ?? [];
  const cv = ms.map((m) => m.cvssV3_1).find(Boolean) ?? ms.map((m) => m.cvssV4_0).find(Boolean) ?? ms.map((m) => m.cvssV3_0).find(Boolean);
  if (cv) out.cvss = { v: cv.version, score: cv.baseScore, severity: cv.baseSeverity, vector: cv.vectorString };
  const ssvc = ms.find((m) => m.other?.type === 'ssvc')?.other?.content;
  if (ssvc) {
    const o = Object.assign({}, ...(ssvc.options ?? []));
    out.ssvc = { exploitation: o.Exploitation ?? '', automatable: o.Automatable ?? '', impact: o['Technical Impact'] ?? '' };
  }
  const cwe = (adp.problemTypes ?? [])
    .flatMap((p) => p.descriptions ?? [])
    .filter((d) => d.type === 'CWE' && d.cweId)
    .map((d) => ({ id: d.cweId, name: String(d.description ?? '').replace(d.cweId, '').trim() }));
  if (cwe.length) out.cwe = cwe;
  const products = (adp.affected ?? [])
    .filter((a) => a.vendor || a.product)
    .slice(0, 5)
    .map((a) => ({
      vendor: a.vendor ?? '',
      product: a.product ?? '',
      versions: (a.versions ?? []).filter((v) => v.status === 'affected' && v.version).slice(0, 5).map((v) => String(v.version)),
    }));
  if (products.length) out.products = products;
  if (!Object.keys(out).length) return null;
  const upd = adp.providerMetadata?.dateUpdated;
  if (upd) out.updated = String(upd).slice(0, 10);
  return out;
};
const vr = {};
let vrFailed = 0;
{
  const targets = Object.keys(cves).filter((c) => /^CVE-\d{4}-\d+$/.test(c));
  log(`vulnrichment: ${targets.length}건 조회`);
  await pool(targets, 8, async (id) => {
    const [, y, n] = /^CVE-(\d{4})-(\d+)$/.exec(id);
    try {
      const txt = await getTextOrNull(`${VR_BASE}/${y}/${Math.floor(Number(n) / 1000)}xxx/${id}.json`);
      const v = txt ? vrOf(JSON.parse(txt)) : null;
      if (v) vr[id] = v;
    } catch {
      vrFailed++; // 이번 실행에서는 건너뜀(다음 빌드에서 다시 시도)
    }
  });
  log(`vulnrichment: ${Object.keys(vr).length}건 보강${vrFailed ? ` (조회 실패 ${vrFailed}건)` : ''}`);
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
w('attack.json', { version: attackVersion, tactics, techniques, atomics });
w('vulnrichment.json', Object.fromEntries(Object.entries(vr).sort(([a], [b]) => (a < b ? -1 : 1))));
w('weekly.json', weeks);
w('meta.json', {
  builtAt: new Date().toISOString(),
  sigma: { commit: sigmaCommit, date: sigmaCommitDate, rules: rules.length },
  kev: { catalogVersion: kevRaw.catalogVersion, dateReleased: kevRaw.dateReleased, count: Object.keys(kev).length },
  attack: { version: attackVersion },
  nvd: { enriched: nvdCount },
  vulnrichment: { enriched: Object.keys(vr).length, failed: vrFailed },
  atomics: { techniques: Object.keys(atomics).length },
});
log('완료 →', OUT);
