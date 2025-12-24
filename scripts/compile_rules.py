import os
import yaml
from analyzer.crs_extractor import extract_rules_from_conf

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VENDOR_RULES_DIR = os.path.join(BASE_DIR, "vendor", "crs", "rules")
OUT_PATH = os.path.join(BASE_DIR, "config", "rules_compiled.yml")


def category_from_filename(fname: str) -> str:
    fname = fname.upper()
    if "REQUEST-941-" in fname:
        return "xss"
    if "REQUEST-942-" in fname:
        return "sqli"
    if "REQUEST-932-" in fname:
        # CRS calls this RCE, but it includes lots of command execution patterns
        return "rce"
    if "REQUEST-930-" in fname:
        return "lfi"
    if "REQUEST-933-" in fname:
        return "php"
    return "unknown"


def main() -> None:
    all_rules = []
    summary = {}
    total_skipped = 0

    if not os.path.isdir(VENDOR_RULES_DIR):
        raise FileNotFoundError(f"CRS vendor rules dir not found: {VENDOR_RULES_DIR}")

    for fname in sorted(os.listdir(VENDOR_RULES_DIR)):
        if not fname.endswith(".conf"):
            continue

        conf_path = os.path.join(VENDOR_RULES_DIR, fname)
        extracted, skipped = extract_rules_from_conf(conf_path)
        total_skipped += skipped

        cat = category_from_filename(fname)

        # Convert extracted rules to our internal schema
        converted = []
        for r in extracted:
            # Force score=1 for ALL vulnerabilities (your requirement)
            converted.append({
                "category": cat,
                "id": str(r.get("id", "")),
                "score": 1,
                "regex": True,
                "targets": ["uri", "headers", "body"],
                "patterns": [r["pattern"]],
                "source": fname,
            })

        all_rules.extend(converted)
        summary[fname] = len(converted)

    out_obj = {"version": 1, "rules": all_rules}
    with open(OUT_PATH, "w", encoding="utf-8") as out:
        yaml.safe_dump(out_obj, out, sort_keys=False, allow_unicode=True)

    print(f"[compile_rules] Output: {OUT_PATH}")
    print(f"[compile_rules] Compiled: {len(all_rules)} rules")
    for k, v in summary.items():
        print(f"  - {k}: {v}")
    print(f"[compile_rules] Skipped (non @rx / missing id / etc.): {total_skipped}")


if __name__ == "__main__":
    main()
