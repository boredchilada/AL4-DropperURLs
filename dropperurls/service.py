"""DropperURLs: turn download commands in a script into fetchable uri/ files.

URLCreator only emits a uri/ file when one of its heuristics fires (score at least
minimum_maliciousness, a dot in the path basename, a high port, or a tool name in the path).
IoT botnet loaders defeat all four: they pull extensionless payloads from bare IP literals on
port 80, and the URLs score 0 because nothing has flagged them yet. This service applies a
simpler rule: if the script literally invokes a download utility against a URL, that URL is
worth fetching. No scoring gate.
"""

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultSection, ResultTableSection, ResultTextSection, TableRow
from assemblyline_v4_service.common.task import MaxExtractedExceeded

from dropperurls.analysis import DECODED, Download, behaviour_flags, find_downloads, host_of, is_http, multi_stage

# Hard ceiling regardless of the max_uris submission parameter (service setting max_uris_limit).
DEFAULT_MAX_URIS_LIMIT = 200
EMITTED = "emitted for download"


class DropperURLs(ServiceBase):
    def start(self) -> None:
        self.max_uris_limit = int((self.config or {}).get("max_uris_limit", DEFAULT_MAX_URIS_LIMIT))

    def execute(self, request: ServiceRequest) -> None:
        result = Result()
        request.result = result
        with open(request.file_path, "rb") as handle:
            data = handle.read()

        found, tools = find_downloads(data)
        if not found:
            return  # nothing found: empty result, no "nothing found" section

        # Every URL is listed once, in the table; the other sections only add what is new.
        status = self._emit(request, found) if request.get_param("emit_uris") else {}
        table = self._findings(found, tools, status, request.get_param("tag_non_http"))
        result.add_section(table)
        self._multi_stage(found, table)
        self._chain(data, table)
        self._bare_ip(found, table)
        self._encoded(found, table)

    def _emit(self, request: ServiceRequest, found: dict[str, Download]) -> dict[str, str]:
        """Emit uri/ files for URLDownloader and return each URL's status. One bad URL never fails
        the file. Only written-out HTTP(S) URLs are emitted (see Download.fetchable)."""
        max_uris = max(0, min(int(request.get_param("max_uris")), self.max_uris_limit))
        status: dict[str, str] = {}
        limit_hit = False
        for url, download in found.items():
            if not is_http(url) or not download.fetchable:
                continue
            if limit_hit or sum(s == EMITTED for s in status.values()) >= max_uris:
                status[url] = f"not emitted: limit (max_uris={max_uris})"
                continue
            try:
                # Request metadata (headers, method) another service stored for this URL, if any.
                request.add_extracted_uri("Download command target", url, request.get_uri_metadata(url))
                status[url] = EMITTED
            except MaxExtractedExceeded:
                limit_hit = True  # AssemblyLine's extracted-file limit: this and later URLs are not emitted
                status[url] = "not emitted: AssemblyLine extracted-file limit"
            except Exception as exc:  # noqa: BLE001
                self.log.warning(f"Could not emit uri for {url}: {exc}")
                status[url] = "not emitted: error"
        return status

    @staticmethod
    def _findings(found: dict[str, Download], tools: set[str], status: dict[str, str],
                  tag_non_http: bool) -> ResultTableSection:
        table = ResultTableSection(f"Download commands ({len(found)} URL(s))")
        table.set_heuristic(1)
        for url, download in found.items():
            host, is_ip = host_of(url)
            if not download.fetchable:
                state = "not emitted: unresolved"
            elif not is_http(url):
                state = "not emitted: URLDownloader fetches only HTTP(S)"
            else:
                state = status.get(url, "not emitted: emit_uris is off")
            table.add_row(TableRow({"URL": url, "Command": ", ".join(sorted(download.commands)),
                                    "How found": download.how, "Status": state}))
            if is_http(url) or tag_non_http:
                table.add_tag("network.static.uri", url)
            if host:
                table.add_tag("network.static.ip" if is_ip else "network.static.domain", host)
        for tool in sorted(tools):
            table.add_tag("file.behavior", f"Downloader: {tool}")
        return table

    @staticmethod
    def _multi_stage(found: dict[str, Download], parent: ResultSection) -> None:
        stage = multi_stage(list(found))
        if stage is None:
            return
        host, directory, count = stage
        section = ResultTextSection("Multi-stage dropper")
        section.set_heuristic(2)
        section.add_line(f"{count} distinct download URLs in {host}{directory or '/'}: typical of a loader "
                         "fetching one payload per CPU architecture.")
        parent.add_subsection(section)

    @staticmethod
    def _chain(data: bytes, parent: ResultSection) -> None:
        flags = behaviour_flags(data)
        if not (flags["chmod"] and flags["exec_local"] and flags["self_delete"]):
            return
        section = ResultTextSection("Download, execute and self-delete chain")
        section.set_heuristic(3)
        heuristic = section.heuristic
        if heuristic is not None:
            if flags["chmod_777"]:
                heuristic.add_signature_id("chmod_777")
            heuristic.add_signature_id("exec_downloaded")
            heuristic.add_signature_id("self_delete")
        section.add_line("Script downloads a payload, marks it executable, runs it, then removes it.")
        section.add_tag("file.behavior", "Download and execute")
        section.add_tag("file.behavior", "Self-delete")
        parent.add_subsection(section)

    @staticmethod
    def _encoded(found: dict[str, Download], parent: ResultSection) -> None:
        """Heuristic 5: URLs that only appear once base64, escapes or a piped script are decoded."""
        decoded = sum(download.how == DECODED for download in found.values())
        if not decoded:
            return
        section = ResultTextSection("Download URL hidden by encoding")
        section.set_heuristic(5)
        section.add_line(f"{decoded} URL(s) appear only after decoding base64, escape sequences or a piped script "
                         "(How found: decoded).")
        section.add_tag("file.behavior", "Encoded download URL")
        parent.add_subsection(section)

    @staticmethod
    def _bare_ip(found: dict[str, Download], parent: ResultSection) -> None:
        ip_hosts = sorted({host for host, is_ip in map(host_of, found) if host and is_ip})
        if not ip_hosts:
            return
        section = ResultTextSection("Payload fetched from bare IP address")
        section.set_heuristic(4)
        section.add_line(f"Download host(s) without a DNS name: {', '.join(ip_hosts)}")
        parent.add_subsection(section)
