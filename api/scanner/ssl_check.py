import ssl
import socket
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, List


async def run(target: str) -> Dict[str, Any]:
    host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    findings: List[Dict[str, Any]] = []

    try:
        cert_info = await asyncio.to_thread(_get_cert_info, host)
    except Exception as e:
        return {"module": "ssl_check", "host": host, "error": str(e), "findings": []}

    # Check expiration
    not_after = cert_info.get("not_after")
    if not_after:
        now = datetime.now(timezone.utc)
        if not_after < now:
            findings.append({
                "title": "SSL certificate has expired",
                "severity": "critical",
                "description": f"Certificate expired on {not_after.isoformat()}",
                "remediation": "Renew the SSL certificate immediately.",
            })
        elif (not_after - now).days < 30:
            findings.append({
                "title": f"SSL certificate expires in {(not_after - now).days} days",
                "severity": "medium",
                "description": f"Certificate expires on {not_after.isoformat()}",
                "remediation": "Renew the SSL certificate before expiration.",
            })

    # Check TLS version
    tls_version = cert_info.get("tls_version", "")
    if "TLSv1.0" in tls_version or "TLSv1.1" in tls_version:
        findings.append({
            "title": f"Deprecated TLS version in use: {tls_version}",
            "severity": "high",
            "description": "TLS 1.0 and 1.1 have known vulnerabilities and are deprecated.",
            "remediation": "Disable TLS 1.0/1.1 and enforce TLS 1.2 or 1.3.",
        })

    # Check self-signed
    if cert_info.get("self_signed"):
        findings.append({
            "title": "Self-signed SSL certificate detected",
            "severity": "medium",
            "description": "Self-signed certificates are not trusted by browsers.",
            "remediation": "Use a certificate from a trusted Certificate Authority.",
        })

    return {
        "module": "ssl_check",
        "host": host,
        "certificate": {
            "subject": cert_info.get("subject"),
            "issuer": cert_info.get("issuer"),
            "not_before": cert_info.get("not_before", "").isoformat() if cert_info.get("not_before") else None,
            "not_after": not_after.isoformat() if not_after else None,
            "serial_number": cert_info.get("serial"),
            "san": cert_info.get("san", []),
            "tls_version": tls_version,
        },
        "findings": findings,
    }


def _get_cert_info(host: str, port: int = 443) -> Dict[str, Any]:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
            tls_version = ssock.version()

    subject = dict(x[0] for x in cert.get("subject", ()))
    issuer = dict(x[0] for x in cert.get("issuer", ()))

    not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)

    san = []
    for san_type, san_value in cert.get("subjectAltName", ()):
        san.append(san_value)

    self_signed = subject == issuer

    return {
        "subject": subject.get("commonName", ""),
        "issuer": issuer.get("organizationName", issuer.get("commonName", "")),
        "not_before": not_before,
        "not_after": not_after,
        "serial": cert.get("serialNumber", ""),
        "san": san,
        "tls_version": tls_version,
        "self_signed": self_signed,
    }
