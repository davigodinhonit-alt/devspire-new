import httpx
from typing import Dict, Any, List


MALICIOUS_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://localhost",
]


async def run(target: str) -> Dict[str, Any]:
    url = target if target.startswith("http") else f"https://{target}"
    findings: List[Dict[str, Any]] = []
    tests: List[Dict[str, Any]] = []

    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0, verify=False) as client:
        for origin in MALICIOUS_ORIGINS:
            try:
                resp = await client.get(url, headers={"Origin": origin})
                acao = resp.headers.get("access-control-allow-origin", "")
                acac = resp.headers.get("access-control-allow-credentials", "")

                reflected = acao == origin or acao == "*"
                test_result = {
                    "origin_sent": origin,
                    "acao_returned": acao or "(none)",
                    "acac": acac or "(none)",
                    "reflected": reflected,
                }
                tests.append(test_result)

            except Exception as e:
                tests.append({"origin_sent": origin, "error": str(e)})

        # Also test with target's own subdomain variation
        target_host = url.replace("https://", "").replace("http://", "").split("/")[0]
        evil_sub = f"https://{target_host}.evil.com"
        try:
            resp = await client.get(url, headers={"Origin": evil_sub})
            acao = resp.headers.get("access-control-allow-origin", "")
            tests.append({
                "origin_sent": evil_sub,
                "acao_returned": acao or "(none)",
                "reflected": acao == evil_sub,
            })
        except Exception:
            pass

    # Analyze results
    wildcard = any(t.get("acao_returned") == "*" for t in tests)
    reflects_any = any(t.get("reflected") and t.get("origin_sent") != "*" for t in tests)
    creds_with_wildcard = any(
        t.get("acao_returned") == "*" and t.get("acac", "").lower() == "true" for t in tests
    )

    if reflects_any:
        findings.append({
            "title": "CORS reflects arbitrary Origin header",
            "severity": "high",
            "description": "The server reflects the Origin header in Access-Control-Allow-Origin, allowing any website to make cross-origin requests.",
            "remediation": "Implement a strict allowlist for CORS origins instead of reflecting the request Origin.",
        })

    if wildcard:
        findings.append({
            "title": "CORS wildcard (*) configured",
            "severity": "medium",
            "description": "Access-Control-Allow-Origin is set to *, allowing any origin to access resources.",
            "remediation": "Replace wildcard with specific trusted origins.",
        })

    if creds_with_wildcard:
        findings.append({
            "title": "CORS credentials allowed with wildcard origin",
            "severity": "critical",
            "description": "Access-Control-Allow-Credentials: true combined with wildcard CORS allows credential theft.",
            "remediation": "Never combine Allow-Credentials: true with wildcard or reflected origins.",
        })

    status = "secure"
    if reflects_any or creds_with_wildcard:
        status = "misconfigured"
    elif wildcard:
        status = "wildcard"

    return {
        "module": "cors_check",
        "url": url,
        "status": status,
        "tests": tests,
        "findings": findings,
    }
