import asyncio
import uuid
import re
import ipaddress
from datetime import datetime, timezone
from typing import Dict, Any

from scanner import port_scan, headers, ssl_check, cors_check, dir_enum, subdomain, js_analysis, tech_detect, dns_check, waf_detect

# In-memory scan storage
scans: Dict[str, Dict[str, Any]] = {}

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
]


def validate_target(target: str) -> str:
    """Validate and normalize target. Returns cleaned domain or raises ValueError."""
    target = target.strip().lower()
    target = re.sub(r"^https?://", "", target)
    target = target.rstrip("/").split("/")[0].split(":")[0]

    if not target:
        raise ValueError("Empty target")

    # Block localhost
    if target in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        raise ValueError("Scanning localhost is not allowed")

    # Check if it's an IP address
    is_ip = False
    try:
        ip = ipaddress.ip_address(target)
        is_ip = True
        for network in PRIVATE_RANGES:
            if ip in network:
                raise ValueError(f"Scanning private IP ranges is not allowed: {target}")
    except ValueError as e:
        if "not allowed" in str(e):
            raise
        # Not a valid IP, check if it's a valid domain

    # Domain validation (only if not an IP)
    if not is_ip:
        if not re.match(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$", target):
            raise ValueError(f"Invalid target format: {target}")

    return target


def create_scan(target: str) -> Dict[str, Any]:
    scan_id = uuid.uuid4().hex[:12]
    scan = {
        "scan_id": scan_id,
        "target": target,
        "status": "running",
        "progress": 0,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "completed_at": None,
        "results": {
            "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "modules": {},
        },
        "error": None,
    }
    scans[scan_id] = scan
    return scan


def _count_findings(scan: Dict[str, Any]):
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for module_data in scan["results"]["modules"].values():
        for finding in module_data.get("findings", []):
            sev = finding.get("severity", "info").lower()
            if sev in summary:
                summary[sev] += 1
    scan["results"]["summary"] = summary


async def run_scan(scan_id: str):
    scan = scans.get(scan_id)
    if not scan:
        return

    target = scan["target"]

    try:
        # Phase 1: Reconnaissance (20%)
        phase1 = await asyncio.gather(
            _safe_run(dns_check.run, target),
            _safe_run(tech_detect.run, target),
            _safe_run(waf_detect.run, target),
            return_exceptions=True,
        )
        scan["results"]["modules"]["dns_check"] = _unwrap(phase1[0])
        scan["results"]["modules"]["tech_detect"] = _unwrap(phase1[1])
        scan["results"]["modules"]["waf_detect"] = _unwrap(phase1[2])
        scan["progress"] = 20
        _count_findings(scan)

        # Phase 2: Enumeration (50%)
        phase2 = await asyncio.gather(
            _safe_run(port_scan.run, target),
            _safe_run(subdomain.run, target),
            _safe_run(dir_enum.run, target),
            return_exceptions=True,
        )
        scan["results"]["modules"]["port_scan"] = _unwrap(phase2[0])
        scan["results"]["modules"]["subdomain"] = _unwrap(phase2[1])
        scan["results"]["modules"]["dir_enum"] = _unwrap(phase2[2])
        scan["progress"] = 50
        _count_findings(scan)

        # Phase 3: Vulnerability Analysis (90%)
        phase3 = await asyncio.gather(
            _safe_run(headers.run, target),
            _safe_run(ssl_check.run, target),
            _safe_run(cors_check.run, target),
            _safe_run(js_analysis.run, target),
            return_exceptions=True,
        )
        scan["results"]["modules"]["headers"] = _unwrap(phase3[0])
        scan["results"]["modules"]["ssl_check"] = _unwrap(phase3[1])
        scan["results"]["modules"]["cors_check"] = _unwrap(phase3[2])
        scan["results"]["modules"]["js_analysis"] = _unwrap(phase3[3])
        scan["progress"] = 90
        _count_findings(scan)

        # Phase 4: Finalize
        _count_findings(scan)
        scan["progress"] = 100
        scan["status"] = "completed"
        scan["completed_at"] = datetime.now(timezone.utc).isoformat()

    except Exception as e:
        scan["status"] = "error"
        scan["error"] = str(e)
        scan["completed_at"] = datetime.now(timezone.utc).isoformat()


async def _safe_run(func, target):
    try:
        return await asyncio.wait_for(func(target), timeout=15)
    except asyncio.TimeoutError:
        return {"module": func.__module__.split(".")[-1], "error": "Module timed out (120s)", "findings": []}
    except Exception as e:
        return {"module": func.__module__.split(".")[-1], "error": str(e), "findings": []}


def _unwrap(result):
    if isinstance(result, Exception):
        return {"error": str(result), "findings": []}
    return result
