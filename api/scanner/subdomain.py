import asyncio
import socket
import httpx
from typing import Dict, Any, List

COMMON_SUBDOMAINS = [
    "www", "api", "admin", "dev", "staging", "qa", "test", "beta",
    "cdn", "static", "assets", "media", "images", "img",
    "mail", "smtp", "pop", "imap", "webmail", "mx",
    "app", "portal", "dashboard", "panel", "cp",
    "db", "database", "mysql", "postgres", "mongo", "redis",
    "git", "gitlab", "github", "svn", "repo",
    "ci", "jenkins", "build", "deploy",
    "docs", "wiki", "help", "support", "status",
    "vpn", "remote", "gateway", "proxy",
    "ns1", "ns2", "dns", "dns1", "dns2",
    "ftp", "sftp", "backup", "bak",
    "sandbox", "demo", "preview", "canary",
    "internal", "intranet", "extranet",
    "auth", "sso", "login", "oauth",
    "monitoring", "grafana", "prometheus", "kibana", "elastic",
    "s3", "storage", "bucket", "files",
    "ws", "websocket", "socket", "realtime",
    "blog", "news", "shop", "store", "pay", "payments",
]


async def resolve_subdomain(subdomain: str, domain: str) -> Dict[str, Any] | None:
    fqdn = f"{subdomain}.{domain}"
    try:
        result = await asyncio.to_thread(socket.getaddrinfo, fqdn, None, socket.AF_INET)
        ip = result[0][4][0] if result else None
        return {"subdomain": fqdn, "ip": ip}
    except (socket.gaierror, OSError):
        return None


async def check_http(client: httpx.AsyncClient, fqdn: str) -> Dict[str, Any]:
    result = {"subdomain": fqdn, "https": None, "http": None}
    for scheme in ("https", "http"):
        try:
            resp = await client.get(f"{scheme}://{fqdn}", follow_redirects=False)
            result[scheme] = {
                "status_code": resp.status_code,
                "size": len(resp.content),
                "server": resp.headers.get("server", ""),
            }
        except Exception:
            pass
    return result


async def run(target: str) -> Dict[str, Any]:
    domain = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    # Remove www. prefix for subdomain enumeration
    if domain.startswith("www."):
        domain = domain[4:]

    findings: List[Dict[str, Any]] = []

    # Phase 1: DNS resolution
    sem = asyncio.Semaphore(20)

    async def limited_resolve(sub):
        async with sem:
            return await resolve_subdomain(sub, domain)

    tasks = [limited_resolve(s) for s in COMMON_SUBDOMAINS]
    dns_results = await asyncio.gather(*tasks, return_exceptions=True)

    resolved = []
    for r in dns_results:
        if isinstance(r, dict) and r is not None:
            resolved.append(r)

    # Phase 2: HTTP check on resolved subdomains
    async with httpx.AsyncClient(timeout=8.0, verify=False) as client:
        http_tasks = [check_http(client, r["subdomain"]) for r in resolved]
        http_results = await asyncio.gather(*http_tasks, return_exceptions=True)

    subdomains = []
    for r in http_results:
        if isinstance(r, dict):
            subdomains.append(r)

    # Generate findings for dev/staging/internal subdomains
    sensitive_subs = {"dev", "staging", "qa", "test", "internal", "intranet", "sandbox", "admin", "debug"}
    for s in subdomains:
        sub_prefix = s["subdomain"].split(".")[0]
        if sub_prefix in sensitive_subs:
            has_http = s.get("https") or s.get("http")
            if has_http:
                findings.append({
                    "title": f"Sensitive subdomain accessible: {s['subdomain']}",
                    "severity": "medium",
                    "description": f"The subdomain {s['subdomain']} is publicly accessible. Non-production environments should be restricted.",
                    "remediation": "Restrict access to internal/development subdomains via VPN or IP allowlist.",
                })

    return {
        "module": "subdomain",
        "domain": domain,
        "total_tested": len(COMMON_SUBDOMAINS),
        "resolved": len(resolved),
        "subdomains": subdomains,
        "findings": findings,
    }
