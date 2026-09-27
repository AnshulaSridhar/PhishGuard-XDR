import re

def extract_iocs(content):

    # Extract clean URLs
    urls = re.findall(
        r'https?://[A-Za-z0-9./?=_-]+',
        content
    )

    emails = re.findall(
        r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}',
        content
    )

    ips = re.findall(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        content
    )

    domains = []

    for url in urls:

        domain = (
            url.replace("https://", "")
            .replace("http://", "")
            .split("/")[0]
        )

        if domain not in domains:
            domains.append(domain)

    return {
        "urls": list(set(urls)),
        "emails": list(set(emails)),
        "ips": list(set(ips)),
        "domains": list(set(domains))
    }