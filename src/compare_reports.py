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
        return {"cves": [], "capabilities": [], "string_findings": 0}
    runs = data.get("runs", [])
    if not runs:
        return {"cves": [], "capabilities": [], "string_findings": 0}

    run = runs[0]

    # Collect rule ids that are CVE/security rules by looking at rule properties/tags
    rules = run.get("tool", {}).get("driver", {}).get("rules", []) or []
    cve_rule_ids = set()
    for rule in rules:
        props = rule.get("properties", {}) or {}
        tags = [t.lower() for t in props.get("tags", [])]
        if any("cve" in t or "security" in t for t in tags):
            if rule.get("id"):
                cve_rule_ids.add(rule.get("id"))

    results = run.get("results", []) or []
    found_cves = set()
    capability_packages = []
    found_capabilities = []
    string_findings = 0

    for res in results:
        rid = res.get("ruleId")
        if rid == "CAPABILITY_ANALYSIS":
            level = res.get("level")
            if level == "CAPABILITY_SAFE" or level == "CAPABILITY_UNSPECIFIED": continue
            export = res.get("export", {}) or {}
            pkg = export.get("package_name")
            if pkg and pkg not in found_capabilities:
                found_capabilities.append(pkg)
                capability_packages.append(f"{pkg} : {level}")
        elif rid == "STRING_ANALYSIS":
            string_findings += 1
        elif rid and rid in cve_rule_ids and rid not in found_cves:
            found_cves.add(rid)

    return {
        "cves": list(found_cves),
        "capabilities": capability_packages,
        "string_findings": string_findings,
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
            custom = {"cves": [], "capabilities": [], "string_findings": 0}

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