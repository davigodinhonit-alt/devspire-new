import asyncio
import dns.resolver
import dns.zone
import dns.query
from typing import Dict, Any, List


RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]


async def run(target: str) -> Dict[str, Any]:
    domain = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]

    findings: List[Dict[str, Any]] = []
    records: Dict[str, List[str]] = {}

    # Resolve DNS records
    for rtype in RECORD_TYPES:
        try:
            answers = await asyncio.to_thread(_resolve, domain, rtype)
            records[rtype] = answers
        except Exception:
            records[rtype] = []

    # Check SPF
    spf_found = False
    for txt in records.get("TXT", []):
        if "v=spf1" in txt:
            spf_found = True
            if "+all" in txt:
                findings.append({
                    "title": "SPF record uses +all (allows any sender)",
                    "severity": "high",
                    "description": "The SPF record ends with +all, which allows any IP to send email for this domain.",
                    "remediation": "Change +all to -all or ~all in the SPF record.",
                })
            break

    if not spf_found:
        findings.append({
            "title": "No SPF record found",
            "severity": "medium",
            "description": "Missing SPF record allows email spoofing for this domain.",
            "remediation": "Add a TXT record with a valid SPF policy (e.g., v=spf1 include:_spf.google.com -all).",
        })

    # Check DMARC
    dmarc_found = False
    try:
        dmarc_answers = await asyncio.to_thread(_resolve, f"_dmarc.{domain}", "TXT")
        for txt in dmarc_answers:
            if "v=DMARC1" in txt:
                dmarc_found = True
                if "p=none" in txt:
                    findings.append({
                        "title": "DMARC policy set to 'none' (monitoring only)",
                        "severity": "low",
                        "description": "DMARC with p=none does not enforce email authentication.",
                        "remediation": "Set DMARC policy to p=quarantine or p=reject after monitoring.",
                    })
                break
        records["DMARC"] = dmarc_answers
    except Exception:
        records["DMARC"] = []

    if not dmarc_found:
        findings.append({
            "title": "No DMARC record found",
            "severity": "medium",
            "description": "Missing DMARC record reduces email spoofing protection.",
            "remediation": "Add a DMARC TXT record at _dmarc.{domain} (e.g., v=DMARC1; p=reject; rua=mailto:dmarc@{domain}).",
        })

    # Check DKIM (common selectors)
    dkim_found = False
    for selector in ["default", "google", "dkim", "mail", "selector1", "selector2", "s1", "s2"]:
        try:
            dkim_answers = await asyncio.to_thread(_resolve, f"{selector}._domainkey.{domain}", "TXT")
            if dkim_answers:
                dkim_found = True
                records[f"DKIM ({selector})"] = dkim_answers
                break
        except Exception:
            continue

    if not dkim_found:
        findings.append({
            "title": "No DKIM record found (common selectors checked)",
            "severity": "low",
            "description": "DKIM signing could not be verified with common selectors.",
            "remediation": "Configure DKIM signing for outbound emails.",
        })

    # Zone transfer attempt
    zone_transfer = False
    for ns in records.get("NS", []):
        try:
            ns_host = ns.rstrip(".")
            z = await asyncio.to_thread(_try_axfr, domain, ns_host)
            if z:
                zone_transfer = True
                findings.append({
                    "title": f"DNS Zone Transfer allowed on {ns_host}",
                    "severity": "high",
                    "description": f"Nameserver {ns_host} allows zone transfer (AXFR), exposing all DNS records.",
                    "remediation": "Disable zone transfers to unauthorized hosts on all nameservers.",
                })
                break
        except Exception:
            continue

    return {
        "module": "dns_check",
        "domain": domain,
        "records": records,
        "spf": spf_found,
        "dmarc": dmarc_found,
        "dkim": dkim_found,
        "zone_transfer": zone_transfer,
        "findings": findings,
    }


def _resolve(domain: str, rtype: str) -> List[str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5
    try:
        answers = resolver.resolve(domain, rtype)
        return [str(rdata) for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []


def _try_axfr(domain: str, nameserver: str):
    try:
        z = dns.zone.from_xfr(dns.query.xfr(nameserver, domain, timeout=5))
        return z
    except Exception:
        return None
