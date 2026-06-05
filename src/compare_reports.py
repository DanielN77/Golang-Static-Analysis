import argparse
import json
import os

def load_json(path: str):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception as e:
        print(f"Failed to load {path}: {e}")
        return None

def parse_custom_sarif(path: str):
    data = load_json(path)
    if not data:
        return {"cve_count": 0, "cves": [], "capabilities": [], "string_findings": 0, "decodings": []}
    runs = data.get("runs", [])
    if not runs:
        return {"cve_count": 0, "cves": [], "capabilities": [], "string_findings": 0, "decoding": []}

    run = runs[0]

    results = run.get("results", []) or []
    found_cves = []
    capability_packages = []
    found_capabilities = []
    decodings = []
    string_findings = 0
    cve_amount = 0

    for res in results:
        rid = res.get("ruleId")
        if rid == "CAPABILITY_ANALYSIS":
            properties = res.get("properties", {}) or {}
            type = properties.get("capability")
            # if type == "CAPABILITY_SAFE" or type == "CAPABILITY_UNSPECIFIED": continue
            pkg = properties.get("package_name")
            if pkg and pkg not in found_capabilities:
                found_capabilities.append(pkg)
                capability_packages.append(f"{pkg} : {type}")
        elif rid == "STRING_ANALYSIS":
            properties = res.get("properties", {}) or {}
            decode_path = properties.get("path")
            if decode_path:
                decodings.append(decode_path)
            string_findings += 1
        elif rid and rid and rid not in found_cves:
            cve_amount += 1
            found_cves.append(rid)

    return {
        "cve_count": cve_amount,
        "cves": list(found_cves),
        "capabilities": capability_packages,
        "string_findings": string_findings,
        "decodings" : decodings
    }

def parse_govuln_sarif(path: str):
    data = load_json(path)
    if not data:
        return {"total": 0, "error": 0, "warning": 0, "note": 0}

    runs = data.get("runs", [])
    if not runs:
        return {"total": 0, "error": 0, "warning": 0, "note": 0}

    run = runs[0]
    results = run.get("results", []) or []

    counts = {"total": len(results), "error": 0, "warning": 0, "note": 0}
    for res in results:
        level = (res.get("level") or "").lower()
        if level in counts:
            counts[level] += 1

    return counts

def process_reports_dir(reports_dir: str) -> int:
    reports_dir = os.path.abspath(reports_dir)
    if not os.path.isdir(reports_dir):
        print(f"Reports directory not found: {reports_dir}")
        return 2

    aggregated = []

    for entry in sorted(os.listdir(reports_dir)):
        repo_dir = os.path.join(reports_dir, entry)
        if not os.path.isdir(repo_dir):
            continue

        custom_path = os.path.join(repo_dir, "custom-report.sarif")
        gov_path = os.path.join(repo_dir, "govulncheck-report.sarif")

        if os.path.exists(custom_path):
            custom = parse_custom_sarif(custom_path)
        else:
            custom = {"cve_count": 0, "cves": [], "capabilities": [], "string_findings": 0}

        if os.path.exists(gov_path):
            gov = parse_govuln_sarif(gov_path)
        else:
            gov = {"total": 0, "error": 0, "warning": 0, "note": 0}

        summary = {"repo": entry, "custom": custom, "govulncheck": gov}
        aggregated.append(summary)

        # Per-repo comparison file
        out_file = os.path.join(repo_dir, "comparison.json")
        try:
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(summary, f, indent=2)
        except Exception as e:
            print(f"Warning: failed to write {out_file}: {e}")

    # Total file/Aggregate file
    total_file = os.path.join(reports_dir, "total.json")
    try:
        with open(total_file, "w", encoding="utf-8") as f:
            json.dump(aggregated, f, indent=2)
        print(f"Wrote {total_file} ({len(aggregated)} repos)")
    except Exception as e:
        print(f"Error: failed to write {total_file}: {e}")
        return 3

    return 0

def main():
    parser = argparse.ArgumentParser(
        description="Compare SARIF reports and aggregate results"
    )
    parser.add_argument("reports_dir", nargs="?", default="../reports")
    args = parser.parse_args()
    return process_reports_dir(args.reports_dir)

if __name__ == "__main__":
    main()