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
}
export interface Week { week: string; added: string[]; modified: string[] }
export interface Meta {
  builtAt: string;
  sigma: { commit: string; date: string; rules: number };
  kev: { catalogVersion: string; dateReleased: string; count: number };
  attack: { version: string };
  nvd: { enriched: number };
}
export interface KoNote { summary: string; what: string; analogy?: string; fp: string; check: string }
