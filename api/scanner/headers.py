import httpx
from typing import Dict, Any, List

SECURITY_HEADERS = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security (HSTS)",
        "severity": "high",
        "description": "HSTS forces browsers to use HTTPS, preventing downgrade attacks and cookie hijacking.",
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy (CSP)",
        "severity": "high",
        "description": "CSP prevents XSS and data injection attacks by controlling resource loading.",
        "remediation": "Implement a strict CSP that limits script sources to trusted origins.",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "medium",
        "description": "Prevents clickjacking by disabling iframe embedding.",
        "remediation": "Add header: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "medium",
        "description": "Prevents MIME type sniffing attacks.",
        "remediation": "Add header: X-Content-Type-Options: nosniff",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "low",
        "description": "Controls how much referrer information is sent with requests.",
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "low",
        "description": "Controls browser feature access (camera, microphone, geolocation).",
        "remediation": "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
    "cross-origin-opener-policy": {
        "name": "Cross-Origin-Opener-Policy",
        "severity": "low",
        "description": "Prevents cross-origin window references for isolation.",
        "remediation": "Add header: Cross-Origin-Opener-Policy: same-origin",
    },
    "cross-origin-resource-policy": {
        "name": "Cross-Origin-Resource-Policy",
        "severity": "low",
        "description": "Prevents resources from being loaded by other origins.",
        "remediation": "Add header: Cross-Origin-Resource-Policy: same-origin",
    },
}

INFO_LEAK_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]


async def run(target: str) -> Dict[str, Any]:
    url = target if target.startswith("http") else f"https://{target}"
    findings: List[Dict[str, Any]] = []

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=10.0, verify=False) as client:
            resp = await client.get(url)

        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        # Check missing security headers
        missing = []
        present = []
        for header_key, info in SECURITY_HEADERS.items():
            if header_key in resp_headers:
                present.append({"header": info["name"], "value": resp_headers[header_key]})
            else:
                missing.append(info["name"])
                findings.append({
                    "title": f"Missing security header: {info['name']}",
                    "severity": info["severity"],
                    "description": info["description"],
                    "remediation": info["remediation"],
                })

        # Check info leak headers
        leaked = []
        for h in INFO_LEAK_HEADERS:
            if h in resp_headers:
                leaked.append({"header": h, "value": resp_headers[h]})
                findings.append({
                    "title": f"Information disclosure via '{h}' header",
                    "severity": "low",
                    "description": f"The '{h}' header reveals server technology: {resp_headers[h]}",
                    "remediation": f"Remove or obfuscate the '{h}' header in server configuration.",
                })

        return {
            "module": "headers",
            "url": url,
            "status_code": resp.status_code,
            "present_headers": present,
            "missing_headers": missing,
            "info_leak_headers": leaked,
            "findings": findings,
        }
    except Exception as e:
        return {
            "module": "headers",
            "url": url,
            "error": str(e),
            "findings": [],
        }
