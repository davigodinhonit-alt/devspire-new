from typing import Dict, Any, List


def generate_report(scan: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a structured report from scan results."""
    target = scan["target"]
    summary = scan["results"]["summary"]
    modules = scan["results"]["modules"]

    # Calculate security score (0-100)
    total_findings = sum(summary.values())
    deductions = (
        summary["critical"] * 25
        + summary["high"] * 15
        + summary["medium"] * 8
        + summary["low"] * 3
        + summary["info"] * 1
    )
    score = max(0, 100 - deductions)

    # Grade
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    # Collect all findings sorted by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings: List[Dict[str, Any]] = []
    for module_name, module_data in modules.items():
        for finding in module_data.get("findings", []):
            all_findings.append({
                **finding,
                "module": module_name,
            })
    all_findings.sort(key=lambda f: severity_order.get(f.get("severity", "info"), 5))

    # Top 5 recommendations
    recommendations = []
    seen_titles = set()
    for f in all_findings:
        if f.get("remediation") and f["title"] not in seen_titles:
            recommendations.append({
                "priority": len(recommendations) + 1,
                "action": f["remediation"],
                "related_finding": f["title"],
                "severity": f["severity"],
            })
            seen_titles.add(f["title"])
            if len(recommendations) >= 5:
                break

    # Technology stack
    tech = modules.get("tech_detect", {}).get("technologies", {})

    # Subdomains
    subs = modules.get("subdomain", {}).get("subdomains", [])

    return {
        "target": target,
        "scan_id": scan["scan_id"],
        "started_at": scan["started_at"],
        "completed_at": scan["completed_at"],
        "score": score,
        "grade": grade,
        "summary": summary,
        "total_findings": total_findings,
        "findings": all_findings,
        "recommendations": recommendations,
        "technologies": tech,
        "subdomains": subs,
        "modules": {name: {"findings_count": len(data.get("findings", []))} for name, data in modules.items()},
    }
