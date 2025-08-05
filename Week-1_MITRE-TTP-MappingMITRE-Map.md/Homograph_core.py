import unicodedata
import string
from urllib.parse import urlparse

standard_chars = set(string.ascii_letters + string.digits + string.punctuation + " ")
safe_invisible_chars = {'\n', '\r', '\t'}

allowed_chars = standard_chars.union(safe_invisible_chars)

def is_suspicious(ch):
    return ch not in allowed_chars

def scan_text(text):
    suspicious_chars = filter(is_suspicious, text)

    def get_char_info(ch):
        try:
            name = unicodedata.name(ch)
        except ValueError:
            name = "Unknown or Non-character"
        codepoint = f"U+{ord(ch):04X}"
        return (ch, name, codepoint)

    return list(map(get_char_info, suspicious_chars))

def extract_domain(url):
    parsed = urlparse(url)
    return parsed.netloc or parsed.path

def scan_domain(domain_or_url):
    domain = extract_domain(domain_or_url)
    return scan_text(domain)

if __name__ == "__main__":
    urls = [
        "https://www.faceboоk.com", 
        "http://twіtter.com",       
        "https://ɡithub.com",       
        "https://google.com"        
    ]

    for url in urls:
        print(f"\nScanning: {url}")
        results = scan_domain(url)
        if results:
            for ch, name, codepoint in results:
                print(f"Suspicious: {ch} | {name} | {codepoint}")
        else:
            print("No suspicious characters found.")
