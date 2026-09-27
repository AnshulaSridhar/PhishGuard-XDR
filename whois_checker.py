import whois

def domain_info(domain):

    try:
        w = whois.whois(domain)

        return {
            "domain": domain,
            "registrar": str(w.registrar),
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date)
        }

    except Exception as e:

        return {
            "domain": domain,
            "error": str(e)
        }