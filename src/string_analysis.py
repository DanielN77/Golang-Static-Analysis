import base64
import re


URL_RE = re.compile(r"(https?|ftp|file)://[^\s\"'`<>]+|(?:javascript|data|vbscript):[^\s\"'`<>]+", re.I)

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


def scan_string(value):
    results = []

    direct = looks_interesting(value)
    if direct:
        results.append({
            "type": "plain",
            "value": value,
            "matches": direct,
        })

    b64 = base64_to_string(value)
    if b64:
        matches = looks_interesting(b64)
        results.append({
            "type": "base64",
            "value": value,
            "decoded": b64,
            "matches": matches,
        })

    hx = hex_to_string(value)
    if hx:
        matches = looks_interesting(hx)
        results.append({
            "type": "hex",
            "value": value,
            "decoded": hx,
            "matches": matches,
        })

    ba = byte_array_to_string(value)
    if ba:
        matches = looks_interesting(ba)
        results.append({
            "type": "byte_array",
            "value": value,
            "decoded": ba,
            "matches": matches,
        })

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

    for value in extract_go_strings(source):
        results.extend(scan_string(value))

    for match in BYTE_ARRAY_RE.finditer(source):
        results.extend(scan_string(match.group(0)))

    return results


def scan_go_file(path):
    with open(path, "r") as file:
        source = file.read()

    return scan_go_source(source)
