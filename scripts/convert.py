#!/usr/bin/env python3
"""빌드 시점에 Sigma 룰을 SIEM 쿼리로 변환해 public/data/rules/<id>.json 에 `queries`로 합칩니다.

pySigma(LGPL)는 이 스크립트에서만 쓰고 사이트에는 포함되지 않습니다.
변환은 자동이라 필드 이름·로그 소스 매핑은 환경에 맞춰 조정해야 합니다.
설치: python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
"""
import json, sys, warnings
from multiprocessing import Pool
from pathlib import Path

warnings.filterwarnings("ignore")
ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "public" / "data" / "rules"

try:
    from sigma.collection import SigmaCollection
    from sigma.backends.splunk import SplunkBackend
    from sigma.pipelines.splunk import splunk_windows_pipeline
    from sigma.backends.elasticsearch import LuceneBackend
    from sigma.pipelines.elasticsearch.windows import ecs_windows
    from sigma.backends.kusto import KustoBackend
    from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline
except ImportError as e:  # pySigma가 없으면 변환만 건너뜁니다
    print(f"[convert] pySigma 미설치로 건너뜀: {e}")
    sys.exit(0)

LABELS = {"splunk": "Splunk SPL", "elastic": "Elastic (Lucene)", "kql": "Microsoft Defender XDR / Sentinel (KQL)"}
_cache = {}


def backend(kind, windows):
    key = (kind, windows)
    if key not in _cache:
        if kind == "splunk":
            _cache[key] = SplunkBackend(splunk_windows_pipeline()) if windows else SplunkBackend()
        elif kind == "elastic":
            _cache[key] = LuceneBackend(ecs_windows()) if windows else LuceneBackend()
        else:  # kql은 Windows 계열 룰만 변환
            _cache[key] = KustoBackend(microsoft_xdr_pipeline()) if windows else None
    return _cache[key]


def convert_one(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    windows = data.get("logsource", {}).get("product") == "windows"
    out = []
    for kind in ("splunk", "elastic", "kql"):
        try:
            b = backend(kind, windows)
            if b is None:
                continue
            # 변환 파이프라인이 룰을 바꾸므로 백엔드마다 새로 읽습니다
            q = b.convert(SigmaCollection.from_yaml(data["raw"]))
            q = "\n".join(map(str, q)).strip() if isinstance(q, list) else str(q).strip()
            if q and len(q) < 20000:
                out.append({"id": kind, "label": LABELS[kind], "query": q})
        except Exception:
            continue
    data["queries"] = out
    path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return path.name, len(out)


if __name__ == "__main__":
    files = sorted(RULES.glob("*.json"))
    if len(sys.argv) > 1:
        files = files[: int(sys.argv[1])]
    with Pool() as pool:
        res = pool.map(convert_one, files, chunksize=25)
    ok = sum(1 for _, n in res if n)
    full = sum(1 for _, n in res if n == 3)
    print(f"[convert] 룰 {len(res)}개 중 {ok}개 변환(3종 모두 {full}개)")
