"""Harvester regressions, centred on the bug that corrupted every published rate.

The Smithery listing endpoint returns overlapping pages. Asking for 500 servers
returned 500 records containing 267 distinct ones, some repeated five times.
Nothing checked, so every per-server rate the corpus produced was inflated by
roughly 1.75x, and the write-up went out with the wrong headline number.

What makes that failure worth a test file rather than a fix: it was invisible
to consistency checking. The totals agreed with each other, the arithmetic
closed, and reviewers verified the numbers against each other rather than
against the data. Only counting distinct identities catches it, so that is
what these assert.

No network. The registry is stubbed, so these run anywhere.
"""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "corpus"))

import harvest  # noqa: E402


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(harvest.time, "sleep", lambda *_: None)


def _stub(monkeypatch, pages, total_pages=99):
    """Serve canned pages, keyed by the page= query parameter."""
    import re

    def fake_get(url, **_):
        page = int(re.search(r"page=(\d+)", url).group(1))
        return {"servers": pages.get(page, []),
                "pagination": {"totalPages": total_pages}}

    monkeypatch.setattr(harvest, "_get", fake_get)


def _names(entries):
    return [e.get("qualifiedName") for e in entries]


def test_overlapping_pages_yield_no_duplicates(monkeypatch):
    """The actual bug: pages that repeat servers must not repeat records."""
    _stub(monkeypatch, {
        1: [{"qualifiedName": f"s{i}"} for i in range(0, 100)],
        2: [{"qualifiedName": f"s{i}"} for i in range(50, 150)],
        3: [{"qualifiedName": f"s{i}"} for i in range(100, 200)],
    })
    names = _names(harvest.list_servers(500))
    assert len(names) == len(set(names)), "duplicate servers entered the corpus"
    assert len(names) == 200


def test_fully_duplicate_pages_terminate(monkeypatch):
    """A registry that loops must not page forever toward an unreachable target."""
    same = [{"qualifiedName": f"s{i}"} for i in range(10)]
    _stub(monkeypatch, {n: same for n in range(1, 50)})
    names = _names(harvest.list_servers(500))
    assert len(names) == 10
    assert len(names) == len(set(names))


def test_target_is_respected_when_supply_is_plentiful(monkeypatch):
    _stub(monkeypatch, {
        1: [{"qualifiedName": f"s{i}"} for i in range(0, 100)],
        2: [{"qualifiedName": f"s{i}"} for i in range(100, 200)],
    })
    assert len(harvest.list_servers(50)) == 50


def test_entries_without_a_name_are_dropped(monkeypatch):
    """A nameless entry cannot be deduped or re-fetched, so it is not a server."""
    _stub(monkeypatch, {1: [
        {"qualifiedName": "a"}, {}, {"qualifiedName": None}, {"qualifiedName": "b"},
    ]}, total_pages=1)
    assert _names(harvest.list_servers(10)) == ["a", "b"]


def test_empty_registry_is_not_an_error(monkeypatch):
    _stub(monkeypatch, {}, total_pages=1)
    assert harvest.list_servers(100) == []


def test_a_failed_fetch_is_recorded_not_dropped(monkeypatch):
    """"Could not read this server" and "this server has no tools" differ.

    Dropping failures would let a bad harvest look like a clean small one,
    which is the same class of error as counting duplicates as servers.
    """
    def boom(url, **_):
        raise RuntimeError("registry down")
    monkeypatch.setattr(harvest, "_get", boom)
    rec = harvest.fetch_tools({"qualifiedName": "some/server"})
    assert rec["qualified_name"] == "some/server"
    assert rec["tools"] == []
    assert "registry down" in rec["error"]


def test_provenance_survives_on_every_record(monkeypatch):
    """Records must stay attributable; the corpus is meant to accumulate."""
    monkeypatch.setattr(harvest, "_get", lambda url, **_: {
        "tools": [{"name": "t", "description": "d"}], "description": "srv"})
    rec = harvest.fetch_tools({"qualifiedName": "ns/name", "useCount": 5})
    for field in ("source", "source_url", "qualified_name", "fetched_at"):
        assert rec[field], f"missing provenance field {field}"
    assert rec["source"] == "smithery-registry"
    assert "ns/name" in rec["source_url"]
