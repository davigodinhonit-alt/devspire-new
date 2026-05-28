"""
DevSpire End-to-End Test Suite
Tests the full pipeline: API → Scanner → Report → PDF
"""
import httpx
import time
import sys
import json
import os

os.environ["PYTHONIOENCODING"] = "utf-8"
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

BASE = os.getenv("TEST_API_URL", "http://localhost:5002")
PASS = 0
FAIL = 0


def test(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} -- {detail}")


def main():
    global PASS, FAIL
    client = httpx.Client(timeout=60.0)

    # ==================================================
    print("\n[1/7] Health Check")
    # ==================================================
    try:
        r = client.get(f"{BASE}/api/health")
        data = r.json()
        test("GET /api/health returns 200", r.status_code == 200)
        test("Status is 'ok'", data.get("status") == "ok")
        test("Version present", "version" in data)
        test("Active scans counter exists", "active_scans" in data)
    except Exception as e:
        test("API reachable", False, str(e))
        print("\n\033[31mAPI not running. Start with: python -m uvicorn app:app --port 5001")
        sys.exit(1)

    # ==================================================
    print("\n[2/7] Input Validation")
    # ==================================================
    # Block localhost
    r = client.post(f"{BASE}/api/scan", json={"target": "localhost"})
    test("Blocks localhost", r.status_code == 400)

    r = client.post(f"{BASE}/api/scan", json={"target": "127.0.0.1"})
    test("Blocks 127.0.0.1", r.status_code == 400)

    # Block private IPs
    r = client.post(f"{BASE}/api/scan", json={"target": "192.168.1.1"})
    test("Blocks 192.168.x.x", r.status_code == 400)

    r = client.post(f"{BASE}/api/scan", json={"target": "10.0.0.1"})
    test("Blocks 10.x.x.x", r.status_code == 400)

    r = client.post(f"{BASE}/api/scan", json={"target": "172.16.0.1"})
    test("Blocks 172.16.x.x", r.status_code == 400)

    # Block empty
    r = client.post(f"{BASE}/api/scan", json={"target": ""})
    test("Blocks empty target", r.status_code == 400 or r.status_code == 422)

    # Block invalid format
    r = client.post(f"{BASE}/api/scan", json={"target": "not a domain!!!"})
    test("Blocks invalid domain", r.status_code == 400)

    # Accept valid domain
    r = client.post(f"{BASE}/api/scan", json={"target": "example.com"})
    if r.status_code == 429:
        print("  [WARN] Rate limited (429). Waiting 10s and retrying...")
        time.sleep(10)
        r = client.post(f"{BASE}/api/scan", json={"target": "example.com"})
    test("Accepts valid domain", r.status_code == 200, f"Got {r.status_code}: {r.text[:100]}")
    scan_id = r.json().get("scan_id", "") if r.status_code == 200 else ""
    test("Returns scan_id", len(scan_id) > 0)

    if not scan_id:
        print("\n  [SKIP] Cannot continue without scan_id. Restart server to reset rate limits.")
        sys.exit(1)

    # ==================================================
    print("\n[3/7] Scan Lifecycle (example.com)")
    # ==================================================
    # Wait for scan to complete
    max_wait = 120
    elapsed = 0
    status = "running"
    scan_data = {}
    while elapsed < max_wait:
        r = client.get(f"{BASE}/api/scan/{scan_id}")
        scan_data = r.json()
        status = scan_data.get("status")
        progress = scan_data.get("progress", 0)
        if status != "running":
            break
        print(f"    ... progress: {progress}%")
        time.sleep(3)
        elapsed += 3

    test("Scan completes (not stuck)", status != "running", f"Still running after {max_wait}s")
    test("Status is 'completed'", status == "completed", f"Got: {status}")
    test("Progress reaches 100", scan_data.get("progress") == 100)
    test("Has started_at timestamp", scan_data.get("started_at") is not None)
    test("Has completed_at timestamp", scan_data.get("completed_at") is not None)

    # ==================================================
    print("\n[4/7] Scanner Modules (10/10)")
    # ==================================================
    modules = scan_data.get("results", {}).get("modules", {})
    expected_modules = [
        "dns_check", "tech_detect", "waf_detect",
        "port_scan", "subdomain", "dir_enum",
        "headers", "ssl_check", "cors_check", "js_analysis",
    ]
    for mod in expected_modules:
        present = mod in modules
        has_findings_key = "findings" in modules.get(mod, {})
        no_error = "error" not in modules.get(mod, {})
        test(f"Module '{mod}' present", present)
        if present:
            test(f"  └─ has 'findings' key", has_findings_key)
            test(f"  └─ no errors", no_error, modules.get(mod, {}).get("error", ""))

    # ==================================================
    print("\n[5/7] Results Integrity")
    # ==================================================
    summary = scan_data.get("results", {}).get("summary", {})
    test("Summary has 'critical' key", "critical" in summary)
    test("Summary has 'high' key", "high" in summary)
    test("Summary has 'medium' key", "medium" in summary)
    test("Summary has 'low' key", "low" in summary)
    test("Summary has 'info' key", "info" in summary)

    total = sum(summary.values())
    test("Total findings > 0", total > 0, f"Got {total}")

    # Count findings across modules match summary
    counted = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for mod_data in modules.values():
        for f in mod_data.get("findings", []):
            sev = f.get("severity", "info")
            if sev in counted:
                counted[sev] += 1
    test("Summary counts match actual findings", counted == summary,
         f"Counted {counted} vs summary {summary}")

    # Check finding structure
    all_findings = []
    for mod_data in modules.values():
        all_findings.extend(mod_data.get("findings", []))
    if all_findings:
        f = all_findings[0]
        test("Finding has 'title'", "title" in f)
        test("Finding has 'severity'", "severity" in f)
        test("Finding has 'description'", "description" in f)
        test("Finding has 'remediation'", "remediation" in f)

    # ==================================================
    print("\n[6/7] Report & PDF Generation")
    # ==================================================
    # JSON report
    r = client.get(f"{BASE}/api/report/{scan_id}/json")
    test("GET /api/report/{id}/json returns 200", r.status_code == 200)
    report = r.json()
    test("Report has 'score' (0-100)", 0 <= report.get("score", -1) <= 100)
    test("Report has 'grade' (A-F)", report.get("grade") in ("A", "B", "C", "D", "F"))
    test("Report has 'findings' list", isinstance(report.get("findings"), list))
    test("Report has 'recommendations'", isinstance(report.get("recommendations"), list))
    test("Report has 'technologies'", "technologies" in report)
    test("Report has 'target'", report.get("target") == "example.com")

    # PDF report
    r = client.get(f"{BASE}/api/report/{scan_id}")
    test("GET /api/report/{id} returns 200", r.status_code == 200)
    test("Content-Type is application/pdf", "application/pdf" in r.headers.get("content-type", ""))
    test("PDF size > 1KB", len(r.content) > 1000, f"Got {len(r.content)} bytes")
    test("PDF starts with %PDF header", r.content[:5] == b"%PDF-")
    test("Content-Disposition has filename", "filename=" in r.headers.get("content-disposition", ""))

    # Report for incomplete scan should fail
    r = client.get(f"{BASE}/api/report/nonexistent123")
    test("Report for invalid scan_id returns 404", r.status_code == 404)

    # ==================================================
    print("\n[7/7] Error Handling")
    # ==================================================
    # Invalid scan ID
    r = client.get(f"{BASE}/api/scan/doesnotexist")
    test("GET invalid scan_id returns 404", r.status_code == 404)

    # Missing body
    r = client.post(f"{BASE}/api/scan", content=b"not json", headers={"Content-Type": "application/json"})
    test("Malformed JSON returns 422", r.status_code == 422)

    # Wrong method
    r = client.get(f"{BASE}/api/scan")
    test("GET /api/scan returns 405", r.status_code == 405)

    # ==================================================
    print("\n" + "=" * 50)
    total_tests = PASS + FAIL
    print(f"Results: {PASS}/{total_tests} passed", end="")
    if FAIL > 0:
        print(f", {FAIL} failed")
    else:
        print(" -- ALL PASSED")
    print("=" * 50)

    sys.exit(0 if FAIL == 0 else 1)


if __name__ == "__main__":
    main()
