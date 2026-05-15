import socket
import ssl
import tldextract
from datetime import datetime


# -------------------------------
# GET DOMAIN
# -------------------------------
def get_domain(url):
    try:
        ext = tldextract.extract(url)
        return ext.domain + "." + ext.suffix
    except:
        return None


# -------------------------------
# DOMAIN AGE (SAFE)
# -------------------------------
def get_domain_age(url):
    try:
        import whois

        domain = get_domain(url)
        if not domain:
            return 0

        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return 0

        age = (datetime.now() - creation_date).days

        if age < 0 or age > 10000:
            return 0

        return age

    except:
        return 0


# -------------------------------
# DNS CHECK
# -------------------------------
def has_dns_record(url):
    try:
        domain = get_domain(url)
        if not domain:
            return 0

        socket.gethostbyname(domain)
        return 1

    except:
        return 0


# -------------------------------
# SSL CHECK
# -------------------------------
def has_valid_ssl(url):
    try:
        domain = get_domain(url)
        if not domain:
            return 0

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(2)
            s.connect((domain, 443))
            cert = s.getpeercert()

        return 1 if cert else 0

    except:
        return 0