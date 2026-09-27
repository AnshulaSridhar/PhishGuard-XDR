def analyze_headers(email_data):

    findings = []

    sender = str(
        email_data.get("from", "")
    ).lower()

    subject = str(
        email_data.get("subject", "")
    ).lower()

    suspicious_tlds = [
        ".ru",
        ".xyz",
        ".top",
        ".tk"
    ]

    for tld in suspicious_tlds:

        if tld in sender:

            findings.append(
                f"Suspicious sender domain uses {tld}"
            )

    trusted_brands = [
        "microsoft",
        "google",
        "paypal",
        "amazon"
    ]

    for brand in trusted_brands:

        if brand in sender and not sender.endswith(".com"):

            findings.append(
                f"Possible {brand} spoofing detected"
            )

    urgency_words = [
        "locked",
        "urgent",
        "verify",
        "suspended",
        "immediately"
    ]

    for word in urgency_words:

        if word in subject:

            findings.append(
                f"Urgent phishing keyword detected: {word}"
            )

    return findings