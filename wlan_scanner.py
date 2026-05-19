import socket
import requests
import scapy.all as scapy
import nmap
import os
import smtplib

from email.message import EmailMessage
from datetime import datetime
from netaddr import EUI
from netaddr.core import NotRegisteredError


scanner = nmap.PortScanner()


def get_vendor(mac_address):
    try:
        mac = EUI(mac_address)
        return mac.oui.registration().org
    except NotRegisteredError:
        return "Unknown Vendor"
    except Exception:
        return "Invalid MAC"


def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "Unknown Hostname"


def guess_device_type(vendor, hostname):
    vendor_l = vendor.lower()
    hostname_l = hostname.lower()

    if "ubee" in vendor_l or "arcadyan" in vendor_l:
        return "Router / Gateway / ISP Equipment"
    if "amazon" in vendor_l or "echo" in hostname_l or "fire" in hostname_l:
        return "Amazon Smart Device"
    if "ring" in vendor_l or "ring" in hostname_l:
        return "Ring Camera / Doorbell"
    if "sony" in vendor_l or "playstation" in hostname_l:
        return "PlayStation / Gaming Console"
    if "apple" in vendor_l or "iphone" in hostname_l or "macbook" in hostname_l:
        return "Apple Device"
    if "samsung" in vendor_l or "tv" in hostname_l:
        return "Samsung / Smart TV"
    if "unknown" in vendor_l and "unknown" in hostname_l:
        return "Unknown Device - Investigate"

    return "General Network Device"


def get_port_warnings(port, service):
    warnings = []

    risky_ports = {
        21: "FTP is unencrypted and can expose usernames/passwords.",
        22: "SSH is open. Make sure strong passwords or keys are used.",
        23: "Telnet is unencrypted and should be disabled if possible.",
        53: "DNS is open. Normal on routers, but investigate if unexpected.",
        80: "HTTP is unencrypted. Use HTTPS where possible.",
        139: "NetBIOS can reveal Windows file-sharing information.",
        443: "HTTPS is open. Usually normal for web/admin interfaces.",
        445: "SMB exposure can be risky if misconfigured.",
        3389: "RDP can be targeted for brute-force attacks.",
        5555: "Port 5555 is often used by Android Debug Bridge or device services.",
        5900: "VNC can allow remote desktop access if weakly secured.",
        8000: "Port 8000 is often used for admin panels, proxies, or web services.",
        8009: "Port 8009 may be AJP or device-specific management traffic.",
        8080: "Alternate web/admin port. Check authentication and updates.",
        9080: "Port 9080 is often an alternate web/application service port."
    }

    if port in risky_ports:
        warnings.append(risky_ports[port])

    if service in ["telnet", "ftp", "http"]:
        warnings.append(f"{service.upper()} may transmit data without encryption.")

    return warnings


def lookup_cves(product, version):
    if not product:
        return []

    query = f"{product} {version}".strip()
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    try:
        response = requests.get(
            url,
            params={
                "keywordSearch": query,
                "resultsPerPage": 3
            },
            timeout=10
        )

        if response.status_code != 200:
            return []

        data = response.json()
        results = []

        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cve_id = cve.get("id", "Unknown CVE")
            metrics = cve.get("metrics", {})
            score = "N/A"
            severity = "Unknown"

            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]
                score = cvss["cvssData"]["baseScore"]
                severity = cvss["cvssData"]["baseSeverity"]
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]
                score = cvss["cvssData"]["baseScore"]
                severity = cvss["cvssData"]["baseSeverity"]
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]
                score = cvss["cvssData"]["baseScore"]
                severity = cvss.get("baseSeverity", "Unknown")

            results.append({
                "id": cve_id,
                "score": score,
                "severity": severity
            })

        return results

    except Exception:
        return []


def calculate_risk_score(open_ports):
    score = 0

    for item in open_ports:
        score += 1

        if item["warnings"]:
            score += len(item["warnings"]) * 2

        for cve in item["cves"]:
            try:
                cve_score = float(cve["score"])
                if cve_score >= 9:
                    score += 5
                elif cve_score >= 7:
                    score += 4
                elif cve_score >= 4:
                    score += 2
                else:
                    score += 1
            except Exception:
                score += 1

    if score >= 15:
        return score, "High"
    elif score >= 7:
        return score, "Medium"
    elif score > 0:
        return score, "Low"
    else:
        return score, "None"


def email_report(report_file):
    sender_email = os.getenv("SCANNER_EMAIL")
    receiver_email = os.getenv("SCANNER_RECEIVER_EMAIL")
    app_password = os.getenv("SCANNER_APP_PASSWORD")

    if not sender_email or not receiver_email or not app_password:
        print("[!] Email settings missing. Report was not emailed.")
        return

    msg = EmailMessage()
    msg["Subject"] = "WLAN Vulnerability Scan Report"
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg.set_content("Your WLAN vulnerability scan has completed. The report is attached.")

    with open(report_file, "rb") as f:
        msg.add_attachment(
            f.read(),
            maintype="application",
            subtype="octet-stream",
            filename=report_file
        )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
        smtp.login(sender_email, app_password)
        smtp.send_message(msg)

    print("[+] Report emailed successfully.")


def discover_devices(network_range):
    print(f"[*] Scanning for devices in {network_range}...")

    arp_request = scapy.ARP(pdst=network_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered_list = scapy.srp(packet, timeout=2, verbose=0)[0]

    devices = []

    for sent, received in answered_list:
        ip = received.psrc
        mac = received.hwsrc
        vendor = get_vendor(mac)
        hostname = get_hostname(ip)
        device_type = guess_device_type(vendor, hostname)

        devices.append({
            "ip": ip,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "device_type": device_type,
            "open_ports": [],
            "risk_score": 0,
            "risk_level": "None"
        })

    return devices


def scan_ports(ip):
    print(f"\n[+] Scanning ports on {ip}...")

    open_ports = []

    scanner.scan(ip, arguments="-sT -sV -T4")

    if ip in scanner.all_hosts():
        for proto in scanner[ip].all_protocols():
            ports = scanner[ip][proto].keys()

            for port in ports:
                service = scanner[ip][proto][port].get("name", "unknown")
                product = scanner[ip][proto][port].get("product", "")
                version = scanner[ip][proto][port].get("version", "")

                print(f"    Port {port} is open | Service: {service} {product} {version}")

                cves = lookup_cves(product, version)
                warnings = get_port_warnings(port, service)

                open_ports.append({
                    "port": port,
                    "service": service,
                    "product": product,
                    "version": version,
                    "warnings": warnings,
                    "cves": cves
                })
    else:
        print(f"    [!] No response from {ip}")

    return open_ports


def create_report(devices):
    report_file = "scan_report.txt"

    with open(report_file, "w") as report:
        report.write("WLAN Vulnerability Scan Report\n")
        report.write(f"Generated: {datetime.now()}\n\n")

        for device in devices:
            report.write(f"IP: {device['ip']}\n")
            report.write(f"MAC: {device['mac']}\n")
            report.write(f"Vendor: {device['vendor']}\n")
            report.write(f"Hostname: {device['hostname']}\n")
            report.write(f"Device Type Guess: {device['device_type']}\n")
            report.write(f"Risk Score: {device['risk_score']} | Risk Level: {device['risk_level']}\n")

            if device["open_ports"]:
                report.write("Open Ports:\n")

                for item in device["open_ports"]:
                    report.write(
                        f"  - Port {item['port']} | "
                        f"Service: {item['service']} "
                        f"{item['product']} {item['version']}\n"
                    )

                    for warning in item["warnings"]:
                        report.write(f"    WARNING: {warning}\n")

                    if item["cves"]:
                        report.write("    Possible CVEs:\n")

                        for cve in item["cves"]:
                            report.write(
                                f"      - {cve['id']} | CVSS: {cve['score']} | Severity: {cve['severity']}\n"
                            )
                    else:
                        report.write("    Possible CVEs: None found\n")
            else:
                report.write("Open Ports: None found\n")

            report.write("\n-------------------------\n\n")

    return report_file


# MAIN
if __name__ == "__main__":
    local_ip = scapy.get_if_addr(scapy.conf.iface)
    network_range = local_ip.rsplit(".", 1)[0] + ".0/24"

    print(f"[*] Detected local IP: {local_ip}")
    print(f"[*] Using network range: {network_range}")

    found_devices = discover_devices(network_range)

    for device in found_devices:
        print(
            f"\n[+] Found Device - IP: {device['ip']} | "
            f"MAC: {device['mac']} | Vendor: {device['vendor']} | "
            f"Hostname: {device['hostname']} | Type: {device['device_type']}"
        )

        device["open_ports"] = scan_ports(device["ip"])
        device["risk_score"], device["risk_level"] = calculate_risk_score(device["open_ports"])

    report_file = create_report(found_devices)
    email_report(report_file)