import re
import math

# -------------------------------
# BASIC FEATURES
# -------------------------------

def has_ip(url):
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    return 1 if re.search(ip_pattern, url) else 0


def count_special_chars(url):
    return len(re.findall(r'[@\-\_%=]', url))


def count_digits(url):
    return sum(c.isdigit() for c in url)


def has_suspicious_words(url):
    keywords = ["login", "secure", "bank", "verify", "account"]
    return sum(word in url for word in keywords)


def is_https(url):
    return 1 if url.startswith("https") else 0


def count_subdomains(url):
    try:
        return url.count('.') - 1
    except:
        return 0


def url_entropy(url):
    try:
        prob = [float(url.count(c)) / len(url) for c in set(url)]
        return -sum([p * math.log2(p) for p in prob])
    except:
        return 0


# -------------------------------
# FINAL FEATURE FUNCTION
# -------------------------------

def extract_features(url, use_advanced=False):
    try:
        url = str(url).lower().strip()

        features = [
            len(url),                    # 1
            url.count("."),              # 2
            has_ip(url),                 # 3
            count_special_chars(url),    # 4
            count_digits(url),           # 5
            has_suspicious_words(url),   # 6
            is_https(url),               # 7
            count_subdomains(url),       # 8
            url_entropy(url),            # 9
        ]

        # Advanced features (DISABLED during training)
        if use_advanced:
            from advanced_features import (
                get_domain_age,
                has_dns_record,
                has_valid_ssl
            )

            features.extend([
                get_domain_age(url),     # 10
                has_dns_record(url),     # 11
                has_valid_ssl(url)       # 12
            ])
        else:
            # placeholders to maintain feature size
            features.extend([0, 0, 0])

        return features

    except Exception as e:
        print("Feature error:", e)
        return [0] * 12