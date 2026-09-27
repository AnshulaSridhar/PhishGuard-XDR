import streamlit as st
import tempfile

from email_parser import parse_email
from ioc_extractor import extract_iocs
from risk_scorer import calculate_risk
from header_analyzer import analyze_headers
from whois_checker import domain_info
from mitre_mapper import get_mitre_techniques

st.set_page_config(
    page_title="PhishGuard XDR",
    page_icon="🛡️",
    layout="wide"
)

# SIDEBAR

with st.sidebar:

    st.title("🛡️ PhishGuard XDR")

    st.markdown(
        """
        Automated Phishing Investigation Platform
        """
    )

    st.success("Email Parsing")
    st.success("IOC Extraction")
    st.success("Header Analysis")
    st.success("WHOIS Analysis")
    st.success("MITRE ATT&CK")
    st.success("Risk Scoring")

# MAIN PAGE

st.title("🛡️ PhishGuard XDR")

st.subheader(
    "Automated Phishing Investigation Platform"
)

uploaded_file = st.file_uploader(
    "Upload Suspicious Email (.eml)",
    type=["eml"]
)

if uploaded_file:

    with tempfile.NamedTemporaryFile(
        delete=False,
        suffix=".eml"
    ) as tmp:

        tmp.write(
            uploaded_file.getvalue()
        )

        file_path = tmp.name

    # Parse Email

    email_data = parse_email(
        file_path
    )

    content = email_data.get(
        "body",
        ""
    )

    # IOC Extraction

    iocs = extract_iocs(
        content
    )

    # Header Analysis

    header_findings = analyze_headers(
        email_data
    )

    # Risk Score

    score, severity = calculate_risk(
        iocs
    )

    st.success(
        "Analysis Completed Successfully"
    )

    # RISK SECTION

    st.subheader(
        "Risk Assessment"
    )

    col1, col2 = st.columns(2)

    with col1:

        st.metric(
            "Risk Score",
            score
        )

    with col2:

        st.metric(
            "Severity",
            severity
        )

    st.divider()

    # EMAIL DETAILS

    st.subheader(
        "Email Details"
    )

    st.write(
        f"**Subject:** {email_data.get('subject')}"
    )

    st.write(
        f"**From:** {email_data.get('from')}"
    )

    st.write(
        f"**To:** {email_data.get('to')}"
    )

    st.divider()

    # HEADER ANALYSIS

    st.subheader(
        "Header Analysis"
    )

    if header_findings:

        for finding in header_findings:

            st.warning(
                finding
            )

    else:

        st.success(
            "No suspicious header findings detected."
        )

    st.divider()

    # EMAIL BODY

    st.subheader(
        "Email Body"
    )

    st.text_area(
        "Body Content",
        content,
        height=200
    )

    st.divider()

    # IOCS

    st.subheader(
        "Indicators Of Compromise"
    )

    st.write("### URLs")

    if iocs["urls"]:

        for url in iocs["urls"]:

            st.code(url)

    else:

        st.info("No URLs Found")

    st.write("### Domains")

    if iocs["domains"]:

        for domain in iocs["domains"]:

            st.code(domain)

    else:

        st.info("No Domains Found")

    st.write("### IP Addresses")

    if iocs["ips"]:

        for ip in iocs["ips"]:

            st.code(ip)

    else:

        st.info("No IPs Found")

    st.write("### Email Addresses")

    if iocs["emails"]:

        for email in iocs["emails"]:

            st.code(email)

    else:

        st.info("No Emails Found")

    st.divider()

    # WHOIS

    st.subheader(
        "WHOIS Analysis"
    )

    for domain in iocs["domains"]:

        try:

            result = domain_info(
                domain
            )

            st.json(result)

        except Exception as e:

            st.error(
                str(e)
            )

    st.divider()

    # MITRE

    st.subheader(
        "MITRE ATT&CK Mapping"
    )

    mitre_data = get_mitre_techniques()

    for item in mitre_data:

        st.info(
            f"{item['id']} - {item['name']}"
        )

else:

    st.info(
        "Upload a .eml file to begin analysis."
    )