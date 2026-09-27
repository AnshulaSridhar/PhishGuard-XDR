from email_parser import parse_email
from ioc_extractor import extract_iocs
from risk_scorer import calculate_risk
from whois_checker import domain_info
from mitre_mapper import get_mitre_techniques
from report_generator import generate_report
from json_report import save_json
from header_analyzer import analyze_headers

from virustotal_lookup import scan_url
from abuseipdb_lookup import check_ip

print("\n========== PHISHGUARD XDR ==========\n")

# Parse Email
email_data = parse_email(
    "samples/phishing_email.eml"
)
header_findings = analyze_headers(
    email_data
)

print("\n=== EMAIL DATA ===")
print(email_data)

# Extract Body
content = email_data.get("body", "")

print("\n=== EMAIL BODY ===")
print(content)

# Extract IOCs
iocs = extract_iocs(content)

print("\n=== IOCS EXTRACTED ===")
print(iocs)


# WHOIS
whois_results = []

for domain in iocs.get("domains", []):

    try:
        whois_results.append(
            domain_info(domain)
        )

    except Exception as e:

        whois_results.append({
            "domain": domain,
            "error": str(e)
        })

# VirusTotal
vt_results = []

for url in iocs.get("urls", []):

    try:

        vt_results.append({
            "url": url,
            "result": scan_url(url)
        })

    except Exception as e:

        vt_results.append({
            "url": url,
            "error": str(e)
        })

# AbuseIPDB
abuse_results = []

for ip in iocs.get("ips", []):

    try:

        abuse_results.append({
            "ip": ip,
            "result": check_ip(ip)
        })

    except Exception as e:

        abuse_results.append({
            "ip": ip,
            "error": str(e)
        })
  
    score, severity = calculate_risk(
    iocs,
    header_findings,
    vt_results,
    abuse_results
)
# MITRE
mitre_data = get_mitre_techniques()

# Report Data
report_data = {
    "Subject": email_data.get("subject", ""),
    "From": email_data.get("from", ""),
    "To": email_data.get("to", ""),
    "URLs": iocs.get("urls", []),
    "Emails": iocs.get("emails", []),
    "IPs": iocs.get("ips", []),
    "Domains": iocs.get("domains", []),
    "WHOIS Results": whois_results,
    "VirusTotal Results": vt_results,
    "AbuseIPDB Results": abuse_results,
    "MITRE ATT&CK": mitre_data,
    "Risk Score": score,
    "Severity": severity
}

# Save Reports
generate_report(report_data)
save_json(report_data)

# Final Output
print("\n========== RESULTS ==========")

print("\nSubject:")
print(email_data.get("subject", ""))

print("\nFrom:")
print(email_data.get("from", ""))

print("\nTo:")
print(email_data.get("to", ""))

print("\nURLs:")
print(iocs.get("urls", []))

print("\nEmails:")
print(iocs.get("emails", []))

print("\nIPs:")
print(iocs.get("ips", []))

print("\nDomains:")
print(iocs.get("domains", []))

print("\nRisk Score:", score)
print("Severity:", severity)

print("\nReports Generated Successfully!")
print("PDF  -> reports/investigation_report.pdf")
print("JSON -> reports/investigation_report.json")