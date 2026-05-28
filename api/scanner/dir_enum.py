import httpx
import asyncio
from typing import Dict, Any, List

CRITICAL_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/.svn/entries", "/.hg/hgrc",
    "/admin", "/admin/login", "/administrator", "/admin.php",
    "/wp-admin", "/wp-login.php", "/wp-config.php.bak",
    "/api/docs", "/api/swagger", "/swagger.json", "/swagger-ui.html",
    "/api/v1", "/api/v2", "/api/graphql", "/graphql",
    "/phpinfo.php", "/info.php", "/test.php",
    "/server-status", "/server-info", "/.htaccess", "/.htpasswd",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
    "/backup", "/backup.zip", "/backup.sql", "/db.sql", "/dump.sql",
    "/config.yml", "/config.json", "/config.php", "/configuration.php",
    "/database.yml", "/settings.py", "/local_settings.py",
    "/web.config", "/appsettings.json",
    "/.well-known/security.txt", "/security.txt",
    "/.DS_Store", "/Thumbs.db",
    "/package.json", "/composer.json", "/Gemfile",
    "/debug", "/debug/default/view", "/trace", "/elmah.axd",
    "/actuator", "/actuator/health", "/actuator/env",
    "/console", "/terminal", "/shell",
    "/.aws/credentials", "/.docker/config.json",
    "/login", "/signin", "/register", "/signup",
    "/dashboard", "/panel", "/portal", "/cp",
    "/cgi-bin/", "/phpmyadmin/", "/pma/",
    "/status", "/health", "/healthcheck", "/version", "/info",
    "/metrics", "/prometheus",
]


async def check_path(client: httpx.AsyncClient, base_url: str, path: str, baseline_size: int | None) -> Dict[str, Any] | None:
    url = f"{base_url.rstrip('/')}{path}"
    try:
        resp = await client.get(url)
        size = len(resp.content)

        # SPA false positive detection
        if baseline_size and resp.status_code == 200 and abs(size - baseline_size) < 100:
            return None

        if resp.status_code in (200, 301, 302, 403):
            return {
                "path": path,
                "status_code": resp.status_code,
                "size": size,
                "redirect": str(resp.headers.get("location", "")) if resp.status_code in (301, 302) else None,
            }
    except Exception:
        pass
    return None


async def run(target: str) -> Dict[str, Any]:
    url = target if target.startswith("http") else f"https://{target}"
    findings: List[Dict[str, Any]] = []

    async with httpx.AsyncClient(follow_redirects=False, timeout=10.0, verify=False) as client:
        # Get baseline for SPA detection
        baseline_size = None
        try:
            resp = await client.get(f"{url}/this-path-definitely-does-not-exist-12345")
            if resp.status_code == 200:
                baseline_size = len(resp.content)
        except Exception:
            pass

        # Scan paths with concurrency limit
        sem = asyncio.Semaphore(10)

        async def limited_check(path):
            async with sem:
                return await check_path(client, url, path, baseline_size)

        tasks = [limited_check(p) for p in CRITICAL_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    discovered = []
    for r in results:
        if isinstance(r, dict) and r is not None:
            discovered.append(r)

    # Generate findings
    sensitive_patterns = [".env", ".git", ".aws", ".docker", "backup", ".sql", "config", "phpinfo", "htpasswd"]
    for d in discovered:
        path_lower = d["path"].lower()
        if any(p in path_lower for p in sensitive_patterns) and d["status_code"] in (200, 403):
            sev = "critical" if d["status_code"] == 200 else "medium"
            findings.append({
                "title": f"Sensitive file discovered: {d['path']} ({d['status_code']})",
                "severity": sev,
                "description": f"The path {d['path']} returned HTTP {d['status_code']}. This may expose sensitive configuration or data.",
                "remediation": f"Restrict access to {d['path']} or remove it from the web server.",
            })

    return {
        "module": "dir_enum",
        "url": url,
        "total_tested": len(CRITICAL_PATHS),
        "spa_detected": baseline_size is not None,
        "discovered": discovered,
        "findings": findings,
    }
