import re
import httpx
from typing import Dict, Any, List
from bs4 import BeautifulSoup

TECH_SIGNATURES = {
    "frameworks": {
        "React": [r"react\.production\.min\.js", r"__REACT_DEVTOOLS", r"data-reactroot", r"_reactRootContainer"],
        "Angular": [r"ng-version", r"angular\.min\.js", r"ng-app", r"\bng-\w+\b"],
        "Vue.js": [r"vue\.min\.js", r"vue\.runtime", r"data-v-[a-f0-9]", r"__VUE__"],
        "Next.js": [r"_next/static", r"__NEXT_DATA__", r"next/dist"],
        "Nuxt.js": [r"_nuxt/", r"__NUXT__"],
        "Svelte": [r"svelte", r"__svelte"],
        "jQuery": [r"jquery[\.-][\d\.]+\.min\.js", r"jQuery\.fn\.jquery"],
    },
    "cms": {
        "WordPress": [r"wp-content/", r"wp-includes/", r"wp-json/"],
        "Drupal": [r"Drupal\.settings", r"sites/default/files"],
        "Joomla": [r"/media/jui/", r"Joomla!"],
        "Magnolia": [r"\.magnolia/", r"magnolia-public"],
        "Ghost": [r"ghost-[a-z]+\.min\.js"],
    },
    "cdn_waf": {
        "Cloudflare": [r"cf-ray", r"cloudflare", r"__cfduid"],
        "CloudFront": [r"x-amz-cf-id", r"cloudfront\.net"],
        "Akamai": [r"akamai", r"x-akamai"],
        "Fastly": [r"x-served-by.*cache", r"fastly"],
        "Vercel": [r"x-vercel", r"vercel\.app"],
        "Netlify": [r"x-nf-request-id", r"netlify"],
    },
    "server": {
        "Nginx": [r"nginx"],
        "Apache": [r"Apache/[\d\.]+"],
        "IIS": [r"Microsoft-IIS"],
        "Express": [r"x-powered-by.*express"],
        "Gunicorn": [r"gunicorn"],
    },
    "analytics": {
        "Google Analytics": [r"google-analytics\.com", r"googletagmanager\.com", r"gtag/js"],
        "Hotjar": [r"hotjar\.com"],
        "Segment": [r"cdn\.segment\.com"],
        "Mixpanel": [r"mixpanel\.com"],
        "Sentry": [r"sentry\.io", r"Sentry\.init"],
    },
}


async def run(target: str) -> Dict[str, Any]:
    url = target if target.startswith("http") else f"https://{target}"
    detected: Dict[str, List[str]] = {}

    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0, verify=False) as client:
        try:
            resp = await client.get(url)
        except Exception as e:
            return {"module": "tech_detect", "url": url, "error": str(e), "findings": []}

    html = resp.text
    headers_str = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
    combined = f"{html}\n{headers_str}".lower()

    for category, techs in TECH_SIGNATURES.items():
        for tech_name, patterns in techs.items():
            for pattern in patterns:
                if re.search(pattern, combined, re.IGNORECASE):
                    detected.setdefault(category, [])
                    if tech_name not in detected[category]:
                        detected[category].append(tech_name)
                    break

    # Check meta tags
    soup = BeautifulSoup(html, "html.parser")
    generator = soup.find("meta", attrs={"name": "generator"})
    if generator and generator.get("content"):
        detected.setdefault("cms", [])
        gen_val = generator["content"]
        if gen_val not in detected["cms"]:
            detected["cms"].append(gen_val)

    # Check cookies
    cookies = resp.headers.get_list("set-cookie") if hasattr(resp.headers, "get_list") else []
    cookie_str = " ".join(str(c) for c in cookies).lower()
    if "phpsessid" in cookie_str:
        detected.setdefault("server", []).append("PHP")
    if "asp.net" in cookie_str or "aspxauth" in cookie_str:
        detected.setdefault("server", []).append("ASP.NET")
    if "jsessionid" in cookie_str:
        detected.setdefault("server", []).append("Java")

    findings = []
    server_header = resp.headers.get("server", "")
    if server_header:
        findings.append({
            "title": f"Server technology disclosed: {server_header}",
            "severity": "info",
            "description": f"The Server header reveals: {server_header}",
            "remediation": "Remove or obfuscate the Server header.",
        })

    powered_by = resp.headers.get("x-powered-by", "")
    if powered_by:
        findings.append({
            "title": f"X-Powered-By header discloses technology: {powered_by}",
            "severity": "low",
            "description": f"Technology stack revealed via X-Powered-By: {powered_by}",
            "remediation": "Remove the X-Powered-By header.",
        })

    return {
        "module": "tech_detect",
        "url": url,
        "technologies": detected,
        "findings": findings,
    }
