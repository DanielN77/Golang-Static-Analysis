import json

def create_sarif_report(cves, capabilities, string_analysis):
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Langsec Golang Dependency Checker",
                        "informationUri": "https://github.com/DanielN77/Golang-Static-Analysis",
                        "version": "1.0.0",
                        "rules": []
                    }
                },
                "results": []
            }
        ]
    }
    rules = {}
    results = []

    # CVE results
    for module_name, version, vuln_list in cves:
        for vuln in vuln_list:
            rule_id = vuln["go_id"]

            # Rules are a *set* of all vulnerabilities for the whole project
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {
                        "text": f"Known vulnerability in {module_name}"
                    },
                    "properties": {
                        "tags": ["security", "cve"]
                    }
                }

            aliases = ",".join(vuln.get("aliases", []))

            results.append({
                "ruleId": rule_id,
                "level": "error",
                "message": {
                    "text": f"Module {module_name}@{version} is affected by {rule_id}. Aliases: {aliases}"
                },
                "properties":{
                    "module_name": module_name,
                    "version": version,
                    "rule_id": rule_id,
                    "aliases": aliases,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": module_name
                            }
                        }
                    }
                ]
            })

    # Capability results

    # Rules are a *set* of all vulnerabilities for the whole project
    if "CAPABILITY_ANALYSIS" not in rules:
        rules["CAPABILITY_ANALYSIS"] = {
            "id": "CAPABILITY_ANALYSIS",
            "name": "Capability Analysis",
            "shortDescription": {
                "text": "Capability analysis result"
            },
            "properties": {
                "tags": ["capability", "analysis"]
            }
        }

    for package_name, capability in capabilities:
        results.append({
            "ruleId": "CAPABILITY_ANALYSIS",
            "level": "warning",
            "message": {
                "text": f"Package '{package_name}' has capability '{capability}'"
            },
            "properties":{
                "package_name": package_name,
                "capability": capability,
            }
        })

    # String analasis results 

    # Rules are a *set* of all vulnerabilities for the whole project
    if "STRING_ANALYSIS" not in rules:
        rules["STRING_ANALYSIS"] = {
            "id": "STRING_ANALYSIS",
            "name": "String analysis",
            "shortDescription": {
                "text": "Decoded suspicious string"
            },
            "properties": {
                "tags": ["string-analysis", "obfuscation"]
            }
        }

    for file_path, string_entries in string_analysis:
        for entry in string_entries:
            original = entry.get("original", "")
            decoded = entry.get("decoded", "")
            path = ",".join(entry.get("path", []))
            matches = ",".join(entry.get("matches", []))

            results.append({
                "ruleId": "STRING_ANALYSIS",
                "level": "note",
                "message": {
                    "text": f"Decoded string matched patterns [{matches}]. Original='{original}', Decoded='{decoded}', DecodePath='{path}'"
                },
                "properties":{
                    "matches": matches,
                    "original": original,
                    "decoded": decoded,
                    "path": path,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_path
                            }
                        }
                    }
                ]
            })

    sarif["runs"][0]["tool"]["driver"]["rules"] = list(rules.values())
    sarif["runs"][0]["results"] = results

    return sarif

def save_sarif_report(report, output_file="report.sarif"):
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"SARIF report saved to: {output_file}")