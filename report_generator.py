from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import getSampleStyleSheet


def generate_report(data):

    pdf = SimpleDocTemplate(
        "reports/investigation_report.pdf"
    )

    styles = getSampleStyleSheet()

    elements = []

    # Title
    elements.append(
        Paragraph(
            "PhishGuard XDR Investigation Report",
            styles["Title"]
        )
    )

    elements.append(Spacer(1, 20))

    # Executive Summary
    elements.append(
        Paragraph(
            "Executive Summary",
            styles["Heading1"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>Risk Score:</b> {data.get('Risk Score', 'N/A')}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>Severity:</b> {data.get('Severity', 'N/A')}",
            styles["BodyText"]
        )
    )

    elements.append(Spacer(1, 15))

    # Email Information
    elements.append(
        Paragraph(
            "Email Information",
            styles["Heading1"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>Subject:</b> {data.get('Subject', '')}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>From:</b> {data.get('From', '')}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>To:</b> {data.get('To', '')}",
            styles["BodyText"]
        )
    )

    elements.append(Spacer(1, 15))

    # Header Analysis
    elements.append(
        Paragraph(
            "Header Analysis",
            styles["Heading1"]
        )
    )

    for finding in data.get(
        "Header Findings",
        []
    ):

        elements.append(
            Paragraph(
                f"• {finding}",
                styles["BodyText"]
            )
        )

    elements.append(Spacer(1, 15))

    # IOC Analysis
    elements.append(
        Paragraph(
            "Indicators Of Compromise",
            styles["Heading1"]
        )
    )

    elements.append(
        Paragraph(
            f"<b>URLs:</b><br/>{'<br/>'.join(map(str, data.get('URLs', [])))}",
            styles["BodyText"]
        )
    )

    elements.append(Spacer(1, 8))

    elements.append(
        Paragraph(
            f"<b>Domains:</b><br/>{'<br/>'.join(map(str, data.get('Domains', [])))}",
            styles["BodyText"]
        )
    )

    elements.append(Spacer(1, 8))

    elements.append(
        Paragraph(
            f"<b>IPs:</b><br/>{'<br/>'.join(map(str, data.get('IPs', [])))}",
            styles["BodyText"]
        )
    )

    elements.append(Spacer(1, 15))

    # WHOIS
    elements.append(
        Paragraph(
            "WHOIS Analysis",
            styles["Heading1"]
        )
    )

    for item in data.get(
        "WHOIS Results",
        []
    ):

        elements.append(
            Paragraph(
                str(item),
                styles["BodyText"]
            )
        )

    elements.append(Spacer(1, 15))

    # VirusTotal
    elements.append(
        Paragraph(
            "VirusTotal Intelligence",
            styles["Heading1"]
        )
    )

    for item in data.get(
        "VirusTotal Results",
        []
    ):

        elements.append(
            Paragraph(
                str(item),
                styles["BodyText"]
            )
        )

    elements.append(Spacer(1, 15))

    # AbuseIPDB
    elements.append(
        Paragraph(
            "AbuseIPDB Intelligence",
            styles["Heading1"]
        )
    )

    for item in data.get(
        "AbuseIPDB Results",
        []
    ):

        elements.append(
            Paragraph(
                str(item),
                styles["BodyText"]
            )
        )

    elements.append(Spacer(1, 15))

    # MITRE
    elements.append(
        Paragraph(
            "MITRE ATT&CK Mapping",
            styles["Heading1"]
        )
    )

    for item in data.get(
        "MITRE ATT&CK",
        []
    ):

        elements.append(
            Paragraph(
                f"{item['id']} - {item['name']}",
                styles["BodyText"]
            )
        )

    elements.append(Spacer(1, 15))

    # Recommendations
    elements.append(
        Paragraph(
            "Recommendations",
            styles["Heading1"]
        )
    )

    recommendations = [
        "Block identified malicious URLs and domains.",
        "Review sender reputation and domain ownership.",
        "Investigate all extracted IP addresses.",
        "Alert potentially affected users.",
        "Update phishing detection policies and email filtering rules.",
        "Perform VirusTotal and AbuseIPDB reputation checks before user interaction."
    ]

    for rec in recommendations:

        elements.append(
            Paragraph(
                f"• {rec}",
                styles["BodyText"]
            )
        )

    pdf.build(elements)