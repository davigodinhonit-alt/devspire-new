import httpx
from typing import Dict, Any, List

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "server": ["cloudflare"],
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
    },
    "AWS WAF / CloudFront": {
        "headers": ["x-amz-cf-id", "x-amz-cf-pop", "x-amzn-requestid"],
        "server": ["cloudfront", "amazons3"],
    },
    "Akamai": {
        "headers": ["x-akamai-transformed", "akamai-grn"],
        "server": ["akamaighost", "akamai"],
    },
    "Imperva / Incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "cookies": ["incap_ses_", "visid_incap_"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "server": ["sucuri"],
    },
    "F5 BIG-IP": {
        "headers": ["x-wa-info"],
        "server": ["big-ip", "bigip"],
        "cookies": ["BIGipServer"],
    },
    "ModSecurity": {
        "headers": ["x-modsecurity-id"],
        "server": ["mod_security"],
    },
    "Fastly": {
        "headers": ["x-served-by", "x-cache", "x-fastly-request-id"],
        "server": ["fastly"],
    },
    "Vercel": {
        "headers": ["x-vercel-id", "x-vercel-cache"],
        "server": ["vercel"],
    },
}


async def run(target: str) -> Dict[str, Any]:
    url = target if target.startswith("http") else f"https://{target}"
    findings: List[Dict[str, Any]] = []
    detected_wafs: List[str] = []

    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0, verify=False) as client:
        # Normal request
        try:
            resp = await client.get(url)
        except Exception as e:
            return {"module": "waf_detect", "url": url, "error": str(e), "findings": []}

        resp_headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        server_header = resp_headers.get("server", "")
        cookie_header = " ".join(resp.headers.get_list("set-cookie")) if hasattr(resp.headers, "get_list") else ""
        cookie_header = cookie_header.lower()

        for waf_name, signatures in WAF_SIGNATURES.items():
            matched = False

            for h in signatures.get("headers", []):
                if h.lower() in resp_headers:
                    matched = True
                    break

            if not matched:
                for s in signatures.get("server", []):
                    if s.lower() in server_header:
                        matched = True
                        break

            if not matched:
                for c in signatures.get("cookies", []):
                    if c.lower() in cookie_header:
                        matched = True
                        break

            if matched:
                detected_wafs.append(waf_name)

        # Test with malicious payload to trigger WAF
        waf_triggered = False
        try:
            payload_url = f"{url}/?q=<script>alert(1)</script>&id=1' OR 1=1--"
            resp_attack = await client.get(payload_url)
            if resp_attack.status_code in (403, 406, 429, 503):
                waf_triggered = True
        except Exception:
            pass

        # Test rate limiting
        rate_limited = False
        try:
            for _ in range(10):
                r = await client.get(url)
                if r.status_code == 429:
                    rate_limited = True
                    break
        except Exception:
            pass

    if detected_wafs:
        findings.append({
            "title": f"WAF/CDN detected: {', '.join(detected_wafs)}",
            "severity": "info",
            "description": f"The target is behind: {', '.join(detected_wafs)}. This may filter attack traffic.",
            "remediation": "N/A — WAF provides an additional layer of defense.",
        })
    else:
        findings.append({
            "title": "No WAF/CDN detected",
            "severity": "low",
            "description": "No Web Application Firewall was detected protecting the target.",
            "remediation": "Consider deploying a WAF (e.g., Cloudflare, AWS WAF) for additional protection.",
        })

    if not rate_limited:
        findings.append({
            "title": "No rate limiting detected",
            "severity": "low",
            "description": "The server did not return HTTP 429 after repeated requests.",
            "remediation": "Implement rate limiting to prevent brute-force and DoS attacks.",
        })

    return {
        "module": "waf_detect",
        "url": url,
        "detected_wafs": detected_wafs,
        "waf_triggered_on_payload": waf_triggered,
        "rate_limiting": rate_limited,
        "findings": findings,
    }
