export interface RuleSlim {
  id: string; t: string; s: string; l: string; d: string; m: string; a: string;
  k: string[]; tc: string[]; c: string[]; kind: string; p: string; cat: string; sv: string;
}
export interface Rule {
  id: string; title: string; status: string; level: string; date: string; modified: string; author: string;
  description: string; references: string[]; falsepositives: string[]; tags: string[];
  tactics: string[]; techniques: string[]; cves: string[];
  logsource: { product: string; category: string; service: string };
  kind: string; path: string; source_url: string; license: string; raw: string;
  queries?: { id: string; label: string; query: string }[];
}
export interface Kev {
  name: string; vendor: string; product: string; added: string; due: string; ransomware: boolean; desc: string;
}
export interface Nvd { published?: string; desc: string; score: number | null; severity: string | null; enriched: boolean }
export type CveMap = Record<string, { rules: string[]; kev?: Kev; nvd?: Nvd }>;
export interface Attack {
  version: string;
  tactics: { short: string; name: string; id?: string }[];
  techniques: Record<string, { name: string; tactics: string[] }>;
  /** Atomic Red Team에 테스트가 있는 기법 ID -> 테스트 수 */
  atomics?: Record<string, number>;
}
/** CISA Vulnrichment(CISA ADP 컨테이너)가 채운 정보. CISA가 보강한 CVE만 들어 있다. */
export interface Vr {
  cvss?: { v: string; score: number; severity: string; vector: string };
  ssvc?: { exploitation: string; automatable: string; impact: string };
  cwe?: { id: string; name: string }[];
  products?: { vendor: string; product: string; versions: string[] }[];
  updated?: string;
}
export type VrMap = Record<string, Vr>;
export interface Week { week: string; added: string[]; modified: string[] }
export interface Meta {
  builtAt: string;
  sigma: { commit: string; date: string; rules: number };
  kev: { catalogVersion: string; dateReleased: string; count: number };
  attack: { version: string };
  nvd: { enriched: number };
  vulnrichment?: { enriched: number; failed: number };
  atomics?: { techniques: number };
}
export interface KoNote { summary: string; what: string; analogy?: string; fp: string; check: string }
