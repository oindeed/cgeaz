"""Shared fakes for the function unit tests: no Azure, no network, no credentials.

The collector and the reports both live in files named function_app.py, so each is
loaded under its own module name.
"""

import importlib.util
import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _load(name: str, rel: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="session")
def collector():
    return _load("collector_app", "functions/collect_assessments/function_app.py")


@pytest.fixture(scope="session")
def reports():
    return _load("reports_app", "functions/reports/function_app.py")


class FakeContainer:
    """Upserts by id, and answers the handful of query shapes the functions use."""

    def __init__(self, items=None):
        self.items = {i["id"]: dict(i) for i in (items or [])}
        self.writes = []

    def upsert_item(self, doc):
        self.items[self.key(doc)] = dict(doc)
        self.writes.append(dict(doc))

    def key(self, doc):
        return doc["id"]

    def read_item(self, item, partition_key):
        from azure.cosmos.exceptions import CosmosResourceNotFoundError
        for doc in self.items.values():
            if doc["id"] == item:
                return dict(doc)
        raise CosmosResourceNotFoundError(message="not found")

    def query_items(self, query, parameters=None, enable_cross_partition_query=False,
                    partition_key=None):
        params = {p["name"]: p["value"] for p in (parameters or [])}
        rows = list(self.items.values())
        if "c.type = 'control-mapping'" in query:
            return [r for r in rows if r.get("type") == "control-mapping"
                    and r.get("controlSource") == "azure-policy"]
        if "c.status = 'succeeded'" in query:
            rows = sorted((r for r in rows if r.get("status") == "succeeded"),
                          key=lambda r: r["collectedAt"], reverse=True)
            return rows[:1]
        if "c.startedAt >= @since" in query:
            return sorted((r for r in rows if r["startedAt"] >= params["@since"]),
                          key=lambda r: r["startedAt"])
        if "c.status = 'Unhealthy'" in query:
            return [r for r in rows if r.get("runId") == params["@run"]
                    and r.get("status") == "Unhealthy"]
        if "ORDER BY c.collectedAt DESC" in query:
            return sorted(rows, key=lambda r: r["collectedAt"], reverse=True)[:1]
        raise AssertionError(f"unexpected query: {query}")


class FakeResponse:
    def __init__(self, payload, status=200):
        self.payload, self.status_code = payload, status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")

    def json(self):
        return self.payload


class FakeSession:
    """Serves queued pages per (method, url-prefix) and records every call."""

    def __init__(self, get_pages=None, post_pages=None, post_status=200):
        self.get_pages = list(get_pages or [])
        self.post_pages = list(post_pages or [])
        self.post_status = post_status
        self.calls = []

    def get(self, url, headers=None, timeout=None):
        self.calls.append(("GET", url, None))
        return FakeResponse(self.get_pages.pop(0))

    def post(self, url, params=None, headers=None, timeout=None):
        self.calls.append(("POST", url, params))
        if self.post_status >= 400:
            return FakeResponse({}, self.post_status)
        return FakeResponse(self.post_pages.pop(0))


class FakeSnapshots(FakeContainer):
    """Partitioned by runId: the same finding id in two runs is two documents."""

    def key(self, doc):
        return (doc["runId"], doc["id"])

    def partition(self, run_id):
        return {k[1]: v for k, v in self.items.items() if k[0] == run_id}


@pytest.fixture
def fakes():
    return FakeContainer, FakeSession


@pytest.fixture
def snapshots_cls():
    return FakeSnapshots
