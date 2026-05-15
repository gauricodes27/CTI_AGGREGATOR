# ioc_extractor.py
import re

IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
DOMAIN_REGEX = r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
URL_REGEX = r"https?://[^\s]+"
MD5_REGEX = r"\b[a-fA-F0-9]{32}\b"
SHA1_REGEX = r"\b[a-fA-F0-9]{40}\b"
SHA256_REGEX = r"\b[a-fA-F0-9]{64}\b"

def extract_iocs(text):
    if not text:
        return {
            "ip": [],
            "domain": [],
            "url": [],
            "hash": []
        }

    return {
        "ip": list(set(re.findall(IP_REGEX, text))),
        "domain": list(set(re.findall(DOMAIN_REGEX, text))),
        "url": list(set(re.findall(URL_REGEX, text))),
        "hash": list(set(
            re.findall(MD5_REGEX, text)
            + re.findall(SHA1_REGEX, text)
            + re.findall(SHA256_REGEX, text)
        ))
    }