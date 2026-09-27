def calculate_risk(
    iocs,
    header_findings=None,
    vt_results=None,
    abuse_results=None
):

    score = 0

    score += len(iocs["urls"]) * 30
    score += len(iocs["domains"]) * 25
    score += len(iocs["emails"]) * 10
    score += len(iocs["ips"]) * 20

    if header_findings:
        score += len(header_findings) * 10

    if vt_results:

        for item in vt_results:

            if "error" not in item:
                score += 25

    if abuse_results:

        for item in abuse_results:

            if "error" not in item:
                score += 20

    if score >= 100:
        severity = "CRITICAL"

    elif score >= 70:
        severity = "HIGH"

    elif score >= 40:
        severity = "MEDIUM"

    else:
        severity = "LOW"

    return score, severity