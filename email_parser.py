from email import policy
from email.parser import BytesParser

def parse_email(filepath):

    with open(filepath, "rb") as f:

        msg = BytesParser(
            policy=policy.default
        ).parse(f)

    body = ""

    if msg.get_body():

        body = msg.get_body(
            preferencelist=("plain")
        ).get_content()

    return {
        "from": msg.get("From"),
        "to": msg.get("To"),
        "subject": msg.get("Subject"),
        "body": body
    }