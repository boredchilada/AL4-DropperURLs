"""Pure pattern matching for DropperURLs. No AssemblyLine imports."""

import base64
import binascii
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlparse

# Utilities that pull a remote file down to disk.
DOWNLOAD_CMD_RE = re.compile(
    rb"\b(?:busybox\s+)?(wget|curl|tftp|ftpget|ftp|certutil|"
    rb"Invoke-WebRequest|iwr|Start-BitsTransfer|DownloadFile|DownloadString|"
    rb"urlretrieve|urlopen|requests\.get)\b",
    re.IGNORECASE,
)

# Conservative terminator set so trailing shell syntax is not swallowed.
URL_RE = re.compile(rb"(?:https?|ftps?|tftp)://[^\s'\"<>\\|;,)\]}]+", re.IGNORECASE)

# `tftp -g -r <file> <host>` and `tftp <host> -c get <file>` carry no URL at all.
TFTP_GR_RE = re.compile(rb"\btftp\b[^\n;]*?-r\s+(\S+)[^\n;]*?\s(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE)
TFTP_HG_RE = re.compile(rb"\btftp\b\s+(\d{1,3}(?:\.\d{1,3}){3})[^\n;]*?\s-c\s+get\s+(\S+)", re.IGNORECASE)

CHMOD_RE = re.compile(rb"\bchmod\s+(?:[0-7]{3,4}|[+aug]*\+x)\b", re.IGNORECASE)
CHMOD_777_RE = re.compile(rb"\bchmod\s+777\b", re.IGNORECASE)
SELF_DELETE_RE = re.compile(rb"\brm\s+-[rf]{1,2}\b", re.IGNORECASE)
EXEC_LOCAL_RE = re.compile(rb"(?:^|[;&|]\s*)\./\S+", re.MULTILINE)


def host_of(url: str) -> tuple[str | None, bool]:
    """(host, is_ip); (None, False) when the URL has no parseable host."""
    try:
        host = urlparse(url).hostname
    except ValueError:
        return None, False
    if not host:
        return None, False
    try:
        ipaddress.ip_address(host)
        return host, True
    except ValueError:
        return host, False


def harvest(data: bytes) -> tuple[dict[str, set[str]], set[str]]:
    """Download URLs that a download utility is actually invoked against.

    Returns ({url: commands}, tools seen), URLs in order of first appearance. A URL only
    counts when it is on a line that also invokes a download tool, which keeps
    `echo "http://..."` out of the fetch set. A commented-out download command still counts:
    attackers comment out backup hosts, and those are worth fetching.
    """
    found: dict[str, set[str]] = {}
    tools: set[str] = set()

    for line in data.splitlines():
        cmds = {m.group(1).decode("utf-8", "replace").lower() for m in DOWNLOAD_CMD_RE.finditer(line)}
        if not cmds:
            continue
        tools |= cmds
        for m in URL_RE.finditer(line):
            url = m.group(0).decode("utf-8", "replace").rstrip(".,'\"")
            found.setdefault(url, set()).update(cmds)

    # tftp forms that carry no URL: synthesise one so they are still reported.
    for rx, file_first in ((TFTP_GR_RE, True), (TFTP_HG_RE, False)):
        for m in rx.finditer(data):
            a, b = m.group(1).decode("utf-8", "replace"), m.group(2).decode("utf-8", "replace")
            fname, host = (a, b) if file_first else (b, a)
            found.setdefault(f"tftp://{host}/{fname.lstrip('/')}", set()).add("tftp")
            tools.add("tftp")

    return found, tools


def behaviour_flags(data: bytes) -> dict[str, bool]:
    """Signs of the fetch, chmod, execute, delete chain."""
    return {
        "chmod": bool(CHMOD_RE.search(data)),
        "chmod_777": bool(CHMOD_777_RE.search(data)),
        "exec_local": bool(EXEC_LOCAL_RE.search(data)),
        "self_delete": bool(SELF_DELETE_RE.search(data)),
    }


def multi_stage(urls: list[str]) -> tuple[str, str, int] | None:
    """(host, directory, count) when the URLs look like a loader fetching one payload per
    architecture: three or more distinct URLs in one directory of one host, from a bare IP address
    or with mostly extensionless file names. Legitimate installers also download several files, but
    from several hosts and directories, or with ordinary extensions (.gpg, .deb, .tar.gz)."""
    directories: dict[tuple[str, str], list[str]] = {}
    for url in urls:
        host, _ = host_of(url)
        if host:
            directories.setdefault((host, urlparse(url).path.rsplit("/", 1)[0]), []).append(url)
    if not directories:
        return None
    (host, directory), group = max(directories.items(), key=lambda item: len(item[1]))
    if len(group) < 3:
        return None
    bare_ip = host_of(group[0])[1]
    extensionless = sum("." not in url.rsplit("/", 1)[-1] for url in group)
    return (host, directory, len(group)) if bare_ip or extensionless * 2 >= len(group) else None


def is_http(url: str) -> bool:
    return url.lower().startswith(("http://", "https://"))


# ---- Seeing through variables, encodings and raw sockets ---------------------------------

# How a URL was found, in order of preference: a URL keeps the first way it was found.
LITERAL, SCHEMELESS, RAW_TCP, VARIABLE, DECODED = "literal", "no scheme", "raw TCP", "variable", "decoded"
# Limits that keep hostile scripts from exploding the work.
MAX_VALUES_PER_VARIABLE = 8
MAX_EXPANSIONS_PER_LINE = 64
MAX_EXPANSION_DEPTH = 4
MAX_DECODE_DEPTH = 2
MAX_URLS = 500

IFS_RE = re.compile(rb"\$\{IFS\}|\$IFS\b")
# NAME=value at the start of a statement, a case branch or a command prefix (also after
# export/local/readonly/declare).
# The name must follow a delimiter or whitespace; a lookbehind keeps the delimiter from overlapping
# the optional keyword's whitespace, which made long whitespace runs backtrack quadratically.
ASSIGN_RE = re.compile(
    rb"(?:^|(?<=[;&|()\s]))(?:(?:export|local|readonly)[ \t]+|declare[ \t]+(?:-\w+[ \t]+)*)?"
    rb"([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"\n]*\"|'[^'\n]*'|[^\s;&|`()]*)",
    re.MULTILINE,
)
# $NAME, ${NAME} and ${NAME:-default} / ${NAME-default} / ${NAME:=default}.
VAR_RE = re.compile(rb"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?[-=]([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")
UNRESOLVED = b"\x00"
# $(echo <base64> | base64 -d) and the backtick form, decoded in place.
INLINE_B64_RE = re.compile(
    rb"(?:\$\(|`)\s*(?:echo|printf)\s+(?:-n\s+)?['\"]?([A-Za-z0-9+/=]{8,})['\"]?\s*\|\s*base64\s+(?:-d|--decode|-D)\s*(?:\)|`)"
)
# A whole base64 script run through a shell: echo <b64> | base64 -d | sh, base64 -d <<< <b64> | bash.
PIPED_B64_RE = re.compile(
    rb"(?:echo|printf)\s+(?:-n\s+)?['\"]?([A-Za-z0-9+/=]{16,})['\"]?\s*\|\s*base64\s+(?:-d|--decode|-D)\s*\|\s*(?:ba|da|z)?sh\b"
    rb"|base64\s+(?:-d|--decode|-D)\s*<<<\s*['\"]?([A-Za-z0-9+/=]{16,})['\"]?\s*\|\s*(?:ba|da|z)?sh\b"
)
# printf '\x68\x74...', echo -e '\150\164...' and bash $'\x68\x74...'.
ESCAPED_RE = re.compile(
    rb"(?:printf\s+|echo\s+-e\s+|echo\s+-ne\s+)['\"]((?:[^'\"\\]|\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}|\\[nrt\\])*\\(?:x[0-9a-fA-F]{2}|[0-7]{3})(?:[^'\"\\]|\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}|\\[nrt\\])*)['\"]"
    rb"|\$'((?:[^'\\]|\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}|\\[nrt\\'])*\\(?:x[0-9a-fA-F]{2}|[0-7]{3})(?:[^'\\]|\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}|\\[nrt\\'])*)'"
)
ESCAPE_RE = re.compile(rb"\\x([0-9a-fA-F]{2})|\\([0-7]{1,3})|\\([nrt\\'])")
# http://c2.ex\am\ple.net/x: the shell drops a backslash before an ordinary character, so the
# real host is c2.example.net. Only a backslash before a letter or digit counts, and a URL needs at
# least two of them: sed patterns such as https:\/\/host\/path escape slashes and dots for
# legitimate reasons.
# A backslash counts only when the URL continues after the escaped character, so a real
# trailing escape such as "...a\n" keeps its meaning.
_URL_CHAR = rb"[^\s'\"<>|;,)\]}]"
_SHELL_ESCAPE = rb"\\[A-Za-z0-9](?=" + _URL_CHAR + rb")"
BACKSLASHED_URL_RE = re.compile(rb"(?:https?|ftps?|tftp)://(?:[^\s'\"<>|;,)\]}\\]|" + _SHELL_ESCAPE + rb")+")
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
HOST_NAME_RE = re.compile(rf"{_LABEL}(?:\.{_LABEL})*")
# wget 198.51.100.7/x: wget and curl assume http:// when the scheme is missing.
SCHEMELESS_RE = re.compile(rb"(?<![\w/:.@=-])(\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?/[^\s'\"<>\\|;,)\]}`$]*)")
DOWNLOAD_TOOL_LINE_RE = re.compile(rb"\b(?:busybox\s+)?(wget|curl|ftpget|tftp)\b", re.IGNORECASE)
# exec 3<>/dev/tcp/HOST/PORT ... GET /path HTTP: a hand-written HTTP download.
DEV_TCP_RE = re.compile(rb"/dev/tcp/([A-Za-z0-9.-]+)/(\d{1,5})")
HTTP_GET_RE = re.compile(rb"GET\s+(/[^\s'\"\\]*)\s+HTTP/1\.[01]")


@dataclass
class Download:
    commands: set[str]
    how: str
    # False for a URL written with an unresolved variable or command substitution: shown and
    # tagged, but not worth handing to URLDownloader.
    fetchable: bool = True


def _decode_escapes(text: bytes) -> bytes:
    def one(m: re.Match[bytes]) -> bytes:
        if m.group(1):
            return bytes([int(m.group(1), 16)])
        if m.group(2):
            return bytes([int(m.group(2), 8) & 0xFF])
        return {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"\\": b"\\", b"'": b"'"}[m.group(3)]
    return ESCAPE_RE.sub(one, text)


def _b64(text: bytes) -> bytes | None:
    """Decoded base64 if it is mostly printable text, else None."""
    try:
        decoded = base64.b64decode(text + b"=" * (-len(text) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in decoded)
    return decoded if decoded and printable / len(decoded) > 0.9 else None


def _without_inserted_backslashes(match: re.Match[bytes]) -> bytes:
    url = match.group(0)
    return url.replace(b"\\", b"") if url.count(b"\\") >= 2 else url


def decoded_layers(data: bytes, depth: int = 0) -> list[bytes]:
    """Versions of the script with encoded parts decoded: inline base64 and escapes replaced in
    place, plus every base64 script piped into a shell (decoded recursively)."""
    layers: list[bytes] = []
    inline = INLINE_B64_RE.sub(lambda m: _b64(m.group(1)) or m.group(0), data)
    inline = ESCAPED_RE.sub(lambda m: _decode_escapes(m.group(1) or m.group(2)), inline)
    inline = BACKSLASHED_URL_RE.sub(_without_inserted_backslashes, inline)
    if inline != data:
        layers.append(inline)
    if depth < MAX_DECODE_DEPTH:
        for m in PIPED_B64_RE.finditer(data):
            script = _b64(m.group(1) or m.group(2))
            if script:
                layers.append(script)
                layers.extend(decoded_layers(script, depth + 1))
    return layers


def variable_values(data: bytes) -> dict[bytes, list[bytes]]:
    """Every value each shell variable is assigned (case branches give several)."""
    values: dict[bytes, list[bytes]] = {}
    for m in ASSIGN_RE.finditer(data):
        value = m.group(2)
        if len(value) >= 2 and value[:1] in (b'"', b"'") and value[-1:] == value[:1]:
            value = value[1:-1]
        options = values.setdefault(m.group(1), [])
        if value and value not in options and len(options) < MAX_VALUES_PER_VARIABLE:
            options.append(value)
    return values


def expand(line: bytes, values: dict[bytes, list[bytes]], depth: int = 0) -> list[bytes]:
    """All expansions of the variables in a line. Unknown variables become UNRESOLVED markers."""
    m = VAR_RE.search(line)
    if not m:
        return [line]
    name = m.group(1) or m.group(3)
    options = list(values.get(name, []))
    if m.group(2) is not None and m.group(2) not in options:
        options.append(m.group(2))  # ${NAME:-default}
    if not options or depth >= MAX_EXPANSION_DEPTH:
        options = [UNRESOLVED]
    out: list[bytes] = []
    for value in options:
        for expanded in expand(line[:m.start()] + value + line[m.end():], values, depth + 1):
            if expanded not in out:
                out.append(expanded)
            if len(out) >= MAX_EXPANSIONS_PER_LINE:
                return out
    return out


def _resolved(text: bytes) -> bytes:
    """Download lines with their variables expanded, one line per combination."""
    values = variable_values(text)
    lines: list[bytes] = []
    for line in text.splitlines():
        if VAR_RE.search(line) and (DOWNLOAD_CMD_RE.search(line) or DEV_TCP_RE.search(line)):
            lines.extend(expand(line, values))
    return b"\n".join(lines)


def schemeless(text: bytes) -> dict[str, set[str]]:
    """IP-literal targets without a scheme on wget/curl/ftpget/tftp lines, as http:// URLs."""
    found: dict[str, set[str]] = {}
    for line in text.splitlines():
        tools = {m.group(1).decode().lower() for m in DOWNLOAD_TOOL_LINE_RE.finditer(line)}
        if not tools:
            continue
        for m in SCHEMELESS_RE.finditer(line):
            found.setdefault("http://" + m.group(1).decode("utf-8", "replace").rstrip(".,'\""), set()).update(tools)
    return found


def raw_tcp(text: bytes) -> dict[str, set[str]]:
    """/dev/tcp connections followed by an HTTP GET within five lines, as http:// URLs.
    A /dev/tcp connection without a GET (a reverse shell, for example) is not a download."""
    found: dict[str, set[str]] = {}
    lines = text.splitlines()
    for index, line in enumerate(lines):
        for m in DEV_TCP_RE.finditer(line):
            host, port = m.group(1).decode(), m.group(2).decode()
            for following in lines[index:index + 6]:
                get = HTTP_GET_RE.search(following)
                if get:
                    netloc = host if port == "80" else f"{host}:{port}"
                    found.setdefault(f"http://{netloc}{get.group(1).decode('utf-8', 'replace')}", set()).add("/dev/tcp")
                    break
    return found


def _real_host(url: str) -> bool:
    """The URL's host is an IP address or a plausible DNS name, not a pattern such as ".*"."""
    host, is_ip = host_of(url)
    return host is not None and (is_ip or HOST_NAME_RE.fullmatch(host) is not None)


def _clean(url: str) -> bool:
    """A usable URL: no unresolved variable, command substitution or placeholder left in it."""
    return UNRESOLVED.decode() not in url and "$" not in url and "`" not in url and _real_host(url)


def find_downloads(data: bytes) -> tuple[dict[str, Download], set[str]]:
    """Download URLs a script fetches, with how each was found.

    Looks at the script as written, with ${IFS} read as a space, with encoded parts decoded,
    and with shell variables expanded on download lines. URLs written out literally are kept
    exactly as before; URLs from the other views are kept only when fully resolved.
    """
    downloads: dict[str, Download] = {}
    tools: set[str] = set()

    def add(found: dict[str, set[str]], how: str, require_clean: bool, text: bytes) -> None:
        for url, commands in found.items():
            if len(downloads) >= MAX_URLS:
                return
            if re.search(re.escape(url.encode("utf-8", "replace")) + rb"[.,'\"]?" + _SHELL_ESCAPE, text):
                continue  # cut off at an inserted backslash; the decoded view carries the whole URL
            if not _real_host(url):
                continue  # a pattern such as ftp://.* is not a download target
            if require_clean and not _clean(url):
                continue
            if url in downloads:
                downloads[url].commands |= commands
            else:
                downloads[url] = Download(set(commands), how, _clean(url))

    literal, literal_tools = harvest(data)
    tools |= literal_tools
    add(literal, LITERAL, require_clean=False, text=data)

    spaced = IFS_RE.sub(b" ", data)
    views = [(spaced, LITERAL)] + [(layer, DECODED) for layer in decoded_layers(spaced)]
    for text, how in views:
        found, view_tools = harvest(text)
        tools |= view_tools
        add(found, how, require_clean=True, text=text)
        add(schemeless(text), SCHEMELESS if how == LITERAL else how, require_clean=True, text=text)
        add(raw_tcp(text), RAW_TCP if how == LITERAL else how, require_clean=True, text=text)
        resolved = _resolved(text)
        found, view_tools = harvest(resolved)
        tools |= view_tools
        via = VARIABLE if how == LITERAL else how
        add(found, via, require_clean=True, text=resolved)
        add(schemeless(resolved), via, require_clean=True, text=resolved)
        add(raw_tcp(resolved), via, require_clean=True, text=resolved)
    if any(d.how == RAW_TCP or "/dev/tcp" in d.commands for d in downloads.values()):
        tools.add("/dev/tcp")
    return downloads, tools
