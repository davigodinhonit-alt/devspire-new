import asyncio
import socket
from typing import List, Dict, Any

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "Submission",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 2049: "NFS",
    2082: "cPanel", 2083: "cPanel SSL", 3000: "Node/Dev", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8000: "HTTP Alt", 8080: "HTTP Proxy", 8443: "HTTPS Alt", 8888: "HTTP Alt",
    9090: "Prometheus", 9200: "Elasticsearch", 27017: "MongoDB",
}


async def grab_banner(host: str, port: int, timeout: float = 3.0) -> str:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        try:
            banner = await asyncio.wait_for(reader.read(1024), timeout=2.0)
            return banner.decode("utf-8", errors="replace").strip()[:200]
        except (asyncio.TimeoutError, Exception):
            return ""
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        return ""


async def check_port(host: str, port: int, timeout: float = 3.0) -> Dict[str, Any] | None:
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        banner = await grab_banner(host, port, timeout)
        service = COMMON_PORTS.get(port, "Unknown")

        return {
            "port": port,
            "state": "open",
            "service": service,
            "banner": banner if banner else None,
        }
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        return None


async def run(target: str) -> Dict[str, Any]:
    host = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    tasks = [check_port(host, port) for port in COMMON_PORTS.keys()]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    open_ports = []
    for r in results:
        if isinstance(r, dict) and r is not None:
            open_ports.append(r)

    open_ports.sort(key=lambda x: x["port"])

    findings = []
    risky_ports = {21, 23, 135, 139, 445, 3389, 5900, 6379, 9200, 27017}
    for p in open_ports:
        if p["port"] in risky_ports:
            findings.append({
                "title": f"Potentially risky port open: {p['port']} ({p['service']})",
                "severity": "medium",
                "description": f"Port {p['port']} ({p['service']}) is open and commonly targeted by attackers.",
                "remediation": f"Restrict access to port {p['port']} via firewall rules if not required.",
            })

    return {
        "module": "port_scan",
        "host": host,
        "total_scanned": len(COMMON_PORTS),
        "open_ports": open_ports,
        "findings": findings,
    }
