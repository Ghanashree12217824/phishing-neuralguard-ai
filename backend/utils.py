import re

def is_valid_url(url):
    pattern = re.compile(
        r'^(https?:\/\/)?'
        r'([a-zA-Z0-9.-]+)'
        r'(\.[a-zA-Z]{2,})'
    )
    return re.match(pattern, url) is not None