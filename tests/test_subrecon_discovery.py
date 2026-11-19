"""The discovery runs when the platform asks for a domain.

The platform publishes one task: the domain to scan.  The discovery
worker is the head of the chain, and it is the only worker that knows
how to find the hosts of a domain.

It did not do it.  The ``single`` path - the one the platform always
takes - seeded the report of the target and republished the target, and
never ran a single discovery tool, so the image carried subfinder,
assetfinder, findomain, vita and Sublist3r and none of them was ever
executed.  A scan of ``*.rapyd.net`` found zero subdomains, and the
only host it ever looked at was the one that was named.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from subrecon.subrecon import subrecon  # noqa: E402


class _Collection:
    """A collection that keeps what was written to it."""

    def __init__(self, documents: list[dict[str, Any]] | None = None) -> None:
        self.documents = list(documents or [])
        self.inserted: list[dict[str, Any]] = []
        self.updated: list[tuple[dict[str, Any], dict[str, Any]]] = []

    def find_one(self, query: dict[str, Any]) -> dict[str, Any] | None:
        for document in self.documents:
            if all(document.get(key) == value for key, value in query.items()):
                return document
        return None

    def insert_one(self, document: dict[str, Any]) -> Any:
        self.inserted.append(document)
        self.documents.append(document)
        return type("Result", (), {"inserted_id": document.get("_id")})()

    def update_one(self, query: dict[str, Any], change: dict[str, Any]) -> Any:
        self.updated.append((query, change))
        return type("Result", (), {"modified_count": 1})()


class _Database:
    def __init__(self) -> None:
        self.collections = {"domains": _Collection(), "reports": _Collection()}

    def collection(self, name: str) -> _Collection:
        return self.collections[name]

    def __getitem__(self, name: str) -> _Collection:
        return self.collections[name]


class _Worker(subrecon):
    """A worker without a configuration file and without a database."""

    #: The base class exposes the logger as a property, so the test
    #: worker carries one of its own.
    log = type("Log", (), {"info": lambda *a, **k: None, "error": lambda *a, **k: None})()

    def __init__(self) -> None:
        self.db = _Database()
        self.sent: list[Any] = []

    def send_task(self, task: Any) -> bool:
        self.sent.append(task)
        return True

    def is_denied_host(self, host: str) -> bool:
        return str(host).endswith("docs.demo.test")


def _worker() -> _Worker:
    return _Worker()


def test_the_hosts_the_discovery_found_are_handed_to_the_fleet():
    worker = _worker()

    worker.dispatch_discovered(
        ["api.demo.test", "shop.demo.test"],
        ["https://api.demo.test"],
        "scanid",
    )

    # Two takeover checks for the hosts that were named, and one scan
    # for the host that answered.
    assert len(worker.sent) == 3
    stages = [task.headers["stage"] for task in worker.sent]
    assert stages == ["takeover", "takeover", "new"]
    assert worker.sent[-1].payload["subdomain"] == "api.demo.test"


def test_a_host_the_scan_excludes_is_not_handed_on():
    worker = _worker()

    worker.dispatch_discovered(
        ["docs.demo.test"],
        ["https://docs.demo.test"],
        "scanid",
    )

    assert worker.sent == []
    assert worker.db.collection("domains").inserted == []


def test_every_host_gets_a_report_of_its_own():
    worker = _worker()

    worker.dispatch_discovered([], ["https://api.demo.test"], "scanid")

    reports = worker.db.collection("reports").inserted
    assert len(reports) == 1
    assert reports[0]["Domain"] == "api.demo.test"


def test_the_host_of_a_url_ignores_the_scheme_and_the_path():
    worker = _worker()

    assert worker.host_of("https://api.demo.test/path?x=1") == "api.demo.test"
    assert worker.host_of("api.demo.test") == "api.demo.test"
    assert worker.host_of("") == ""
