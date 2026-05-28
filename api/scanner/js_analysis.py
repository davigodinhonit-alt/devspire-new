import re
import httpx
from typing import Dict, Any, List
from bs4 import BeautifulSoup

SENSITIVE_PATTERNS = [
    {
        "name": "API Key / Token",
        "pattern": r"""(?:api[_-]?key|apikey|api[_-]?token|access[_-]?token|auth[_-]?token|secret[_-]?key)\s*[:=]\s*['"`]([A-Za-z0-9_\-]{16,})['"`]""",
        "severity": "high",
    },
    {
        "name": "AWS Access Key",
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "critical",
    },
    {
        "name": "AWS Secret Key",
        "pattern": r"""(?:aws[_-]?secret|secret[_-]?access[_-]?key)\s*[:=]\s*['"`]([A-Za-z0-9/+=]{40})['"`]""",
        "severity": "critical",
    },
    {
        "name": "Firebase Config",
        "pattern": r"firebaseConfig\s*=\s*\{[^}]+apiKey[^}]+\}",
        "severity": "medium",
    },
    {
        "name": "Sentry DSN",
        "pattern": r"https://[a-f0-9]{32}@[a-z0-9.]+\.sentry\.io/\d+",
        "severity": "low",
    },
    {
        "name": "Internal API URL",
        "pattern": r"https?://(?:(?:dev|staging|qa|test|sandbox|internal|local)[.-])[a-zA-Z0-9._-]+(?::\d+)?",
        "severity": "medium",
    },
    {
        "name": "Localhost Reference",
        "pattern": r"https?://localhost(?::\d+)?(?:/[^\s'\"]*)?",
        "severity": "low",
    },
    {
        "name": "Private IP",
        "pattern": r"https?://(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)(?::\d+)?",
        "severity": "medium",
    },
    {
        "name": "Google Maps API Key",
        "pattern": r"AIza[0-9A-Za-z_-]{35}",
        "severity": "medium",
    },
    {
        "name": "Slack Webhook",
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+",
        "severity": "high",
    },
    {
        "name": "JWT Token",
        "pattern": r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        "severity": "high",
    },
    {
        "name": "Environment Variable",
        "pattern": r"""(?:process\.env|import\.meta\.env)\.[A-Z_]{3,}""",
        "severity": "info",
    },
]


async def run(target: str) -> Dict[str, Any]:
    url = target if target.startswith("http") else f"https://{target}"
    findings: List[Dict[str, Any]] = []
    scripts_analyzed = []

    async with httpx.AsyncClient(follow_redirects=True, timeout=15.0, verify=False) as client:
        # Get main page and extract script URLs
        try:
            resp = await client.get(url)
            soup = BeautifulSoup(resp.text, "html.parser")
        except Exception as e:
            return {"module": "js_analysis", "url": url, "error": str(e), "findings": []}

        script_urls = []
        for tag in soup.find_all("script", src=True):
            src = tag["src"]
            if src.startswith("//"):
                src = f"https:{src}"
            elif src.startswith("/"):
                src = f"{url.rstrip('/')}{src}"
            elif not src.startswith("http"):
                src = f"{url.rstrip('/')}/{src}"
            script_urls.append(src)

        # Also check inline scripts
        inline_js = "\n".join(tag.string or "" for tag in soup.find_all("script") if not tag.get("src"))
        _analyze_js(inline_js, "inline", findings)

        # Fetch and analyze external scripts (limit to same-origin + first 20)
        base_host = url.replace("https://", "").replace("http://", "").split("/")[0]
        same_origin = [s for s in script_urls if base_host in s][:20]

        for script_url in same_origin:
            try:
                resp = await client.get(script_url)
                js_content = resp.text
                scripts_analyzed.append({
                    "url": script_url,
                    "size": len(js_content),
                })
                _analyze_js(js_content, script_url, findings)
            except Exception:
                continue

    return {
        "module": "js_analysis",
        "url": url,
        "scripts_found": len(script_urls),
        "scripts_analyzed": len(scripts_analyzed),
        "details": scripts_analyzed,
        "findings": findings,
    }


def _analyze_js(content: str, source: str, findings: List[Dict[str, Any]]):
    for pattern_info in SENSITIVE_PATTERNS:
        matches = re.findall(pattern_info["pattern"], content, re.IGNORECASE)
        if matches:
            # Deduplicate
            unique = list(set(m if isinstance(m, str) else m[0] if m else "" for m in matches))[:5]
            findings.append({
                "title": f"{pattern_info['name']} found in {source.split('/')[-1][:50]}",
                "severity": pattern_info["severity"],
                "description": f"Pattern '{pattern_info['name']}' detected in JavaScript source.",
                "evidence": unique,
                "source": source[:200],
                "remediation": "Move sensitive values to server-side environment variables. Never expose secrets in client-side code.",
            })
