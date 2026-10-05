"""Domain ownership for hosted TLS scans (A17): a DNS TXT record the customer publishes.

The customer adds `_quantsiv.<domain>  TXT  "quantsiv-verify=<token>"`; the token is random per
domain and installation. Verification is re-checked before every hosted scan, so a domain that
changes hands stops being scanned. Only the system resolver is consulted (dnspython), never the
domain itself, so verification cannot be used to reach anything.
"""

import re
import secrets

from app.services.ssrf import is_blocked_name

RECORD_PREFIX = "quantsiv-verify="
HOSTNAME = re.compile(r"^(?=.{4,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalise_domain(value: str) -> str:
    """A registrable host name in lower case, or a ValueError with a message safe to show."""
    name = value.strip().lower().rstrip(".")
    if name.startswith(("http://", "https://")):
        name = name.split("/", 2)[2].split("/", 1)[0]
    if not HOSTNAME.match(name) or is_blocked_name(name):
        raise ValueError("Enter a public host name such as api.example.com.")
    return name


def new_verification_token() -> str:
    return secrets.token_urlsafe(24)


def txt_record_name(domain: str) -> str:
    return f"_quantsiv.{domain}"


def expected_record(token: str) -> str:
    return f"{RECORD_PREFIX}{token}"


def lookup_txt(name: str) -> list[str]:
    """TXT strings at `name` through the system resolver; empty when there are none."""
    import dns.resolver

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    try:
        answer = resolver.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.DNSException:
        return []
    values = []
    for record in answer:
        values.append(b"".join(record.strings).decode("utf-8", errors="replace"))
    return values


def check_verification(domain: str, token: str, lookup=lookup_txt) -> bool:
    """True when the TXT record for `domain` carries exactly this token."""
    expected = expected_record(token)
    return any(
        secrets.compare_digest(value.strip(), expected) for value in lookup(txt_record_name(domain))
    )
