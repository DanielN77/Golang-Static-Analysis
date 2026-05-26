# DESCRIPTION
# Script for identifying malicious strings within golang files.
# It scans for all strings including byte arrays, and has the ability
# to decode according to base64, hex, and byte decoding.
# It then tries to match it against malicious patterns e.g. 
# shell scripts, and URLs. 

import base64
import re


URL_RE = re.compile(r"(?:https?://)?[a-zA-Z\-]+\.[a-zA-Z-]{2,}", re.I)
SHELL_RE = re.compile(
    r"/bin/(sh|bash|zsh|dash)|"
    r"\b(sh|bash|zsh|dash)\s+-c\b|"
    r"\bcmd(\.exe)?\s*/c\b|"
    r"\b(powershell|pwsh)(\.exe)?\b|"
    r"\b(curl|wget|nc|ncat|netcat|socat|mkfifo)\b|"
    r"/dev/tcp/|"
    r"\|\s*(sh|bash)\b",
    re.I,
)

BASE64_RE = re.compile(r"\b[A-Za-z0-9+/_-]{12,}={0,2}\b")
HEX_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{2}(?:[\s,._:-]*(?:0x)?[0-9a-fA-F]{2}){3,}\b")
BYTE_ARRAY_RE = re.compile(r"\[\]\s*(?:byte|uint8)\s*\{([^}]*)\}", re.S)

SINGLE_LINE_IMPORT_RE = re.compile(r'import\s+(?:"[^"]*"|`[^`]*`)', re.S)
BLOCK_IMPORT_RE = re.compile(r'import\s*\([^)]*\)', re.S)

def remove_imports(source):
    source = BLOCK_IMPORT_RE.sub('', source)
    source = SINGLE_LINE_IMPORT_RE.sub('', source)
    return source

def bytes_to_string(data):
    return data.decode("utf-8")


def base64_to_string(value):
    value = value.strip()

    try:
        decoded = base64.b64decode(value)
        return bytes_to_string(decoded)
    except:
        return None


def hex_to_string(value):
    hex_pairs = re.findall(r"(?:0x)?([0-9a-fA-F]{2})", value)

    if not hex_pairs:
        return None

    try:
        decoded = bytes(int(pair, 16) for pair in hex_pairs)
        return bytes_to_string(decoded)
    except:
        return None


def byte_array_to_string(value):
    match = BYTE_ARRAY_RE.search(value)

    if not match:
        return None

    body = match.group(1)
    tokens = re.findall(r"0x[0-9a-fA-F]+|\d+", body)

    try:
        decoded = bytes(int(token, 0) for token in tokens if 0 <= int(token, 0) <= 255)
        return bytes_to_string(decoded)
    except:
        return None


def looks_interesting(value):
    findings = []

    if URL_RE.search(value):
        findings.append("url")

    if SHELL_RE.search(value):
        findings.append("shell")

    return findings


def scan_string(value, depth=0, max_depth=10, seen=None, original=None, path=None):
    if depth > max_depth:
        return []
    
    # First iteration
    if seen is None:
        seen = set()
    if original is None:
        original = value
    if path is None:
        path = []
    
    # Cycle detection
    if value in seen:
        return []
    seen.add(value)
    results = []

    direct = looks_interesting(value)
    if direct:
        results.append({
            "original": original,
            "path": path,
            "decoded": value,
            "matches": direct,
        })

    b64 = base64_to_string(value)
    if b64:
        results.extend(scan_string(b64, depth + 1, max_depth, seen.copy(), original, path + ["base64"]))

    ba = byte_array_to_string(value)
    if ba:
        results.extend(scan_string(ba, depth + 1, max_depth, seen.copy(), original, path + ["byte_array"]))
    else:
        hx = hex_to_string(value)
        if hx:
            results.extend(scan_string(hx, depth + 1, max_depth, seen.copy(), original, path + ["hex"]))

    return results


def extract_go_strings(source):
    strings = []

    normal_strings = re.findall(r'"((?:\\.|[^"\\])*)"', source, re.S)
    raw_strings = re.findall(r"`([^`]*)`", source, re.S)

    strings.extend(normal_strings)
    strings.extend(raw_strings)

    return strings


def scan_go_source(source):
    results = []

    source = remove_imports(source)

    for value in extract_go_strings(source):
        results.extend(scan_string(value))

    # For when the encoding chain starts with a byte array, since only strings are extracted from extract_go_strings
    for match in BYTE_ARRAY_RE.finditer(source):
        results.extend(scan_string(match.group(0)))
    return results
