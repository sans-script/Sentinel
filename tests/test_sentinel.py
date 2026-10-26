import json
import os
import sys
import urllib.parse
from pathlib import Path

import paramiko
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import sentinel  # noqa: E402


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_loopback_needs_no_token(host):
    assert sentinel.exposure_error(host, "") is None


@pytest.mark.parametrize("host", ["0.0.0.0", "192.0.2.5", "monitor.example.com"])
def test_other_hosts_require_a_token(host):
    assert sentinel.exposure_error(host, "") is not None
    assert sentinel.exposure_error(host, "a-token") is None


def test_host_key_policies():
    assert isinstance(sentinel.build_host_key_policy("strict"), paramiko.RejectPolicy)
    assert isinstance(sentinel.build_host_key_policy("accept-new"), paramiko.AutoAddPolicy)
    with pytest.raises(ValueError):
        sentinel.build_host_key_policy("off")


def test_rate_limit_blocks_after_the_limit_and_is_per_client():
    sentinel.RATE_LIMIT_LOGS.clear()
    results = [sentinel.check_rate_limit("203.0.113.1", max_reqs=3) for _ in range(5)]
    assert results == [False, False, False, True, True]
    assert sentinel.check_rate_limit("203.0.113.2", max_reqs=3) is False


def test_dotenv_parsing(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text(
        "# comment\n"
        "PLAIN = value # trailing comment\n"
        'QUOTED="two words"\n'
        'ESCAPED="line1\\nline2"\n'
        'MULTI="first\nsecond"\n'
        "\n"
        "NOEQUALS\n",
        encoding="utf-8",
    )
    for name in ("PLAIN", "QUOTED", "ESCAPED", "MULTI"):
        monkeypatch.delenv(name, raising=False)
    sentinel.load_dotenv_file(str(env))
    assert os.environ["PLAIN"] == "value"
    assert os.environ["QUOTED"] == "two words"
    assert os.environ["ESCAPED"] == "line1\nline2"
    assert os.environ["MULTI"] == "first\nsecond"
    for name in ("PLAIN", "QUOTED", "ESCAPED", "MULTI"):
        monkeypatch.delenv(name, raising=False)


class FakeRequest(sentinel.SentinelHandler):
    def __init__(self, headers):
        self.headers = headers


@pytest.fixture
def with_token(monkeypatch):
    monkeypatch.setattr(sentinel, "SENTINEL_API_TOKEN", "s3cret")


def url(query=""):
    return urllib.parse.urlparse("/api/status" + query)


def test_everything_is_open_when_no_token_is_set(monkeypatch):
    monkeypatch.setattr(sentinel, "SENTINEL_API_TOKEN", "")
    assert FakeRequest({}).is_authenticated(url())


def test_token_is_required_and_accepted_three_ways(with_token):
    assert not FakeRequest({}).is_authenticated(url())
    assert not FakeRequest({"Authorization": "Bearer wrong"}).is_authenticated(url())
    assert FakeRequest({"Authorization": "Bearer s3cret"}).is_authenticated(url())
    assert FakeRequest({}).is_authenticated(url("?token=s3cret"))
    assert FakeRequest({"Cookie": "a=b; sentinel_token=s3cret"}).is_authenticated(url())


def test_example_targets_are_well_formed():
    targets = json.loads((ROOT / "config" / "sites.example.json").read_text(encoding="utf-8"))
    assert targets
    for target in targets:
        assert {"name", "url", "ip", "hostname", "type", "size"} <= target.keys()
        assert target["type"] in ("http", "vm")
        assert target["size"] in ("hero", "highlight", "small")
        if target["type"] == "vm":
            assert target["ip"] != "-"


def test_demo_results_cover_every_demo_target():
    targets = json.loads((ROOT / "config" / "sites.demo.json").read_text(encoding="utf-8"))
    results = sentinel.demo_results(targets)
    assert len(results) == len(targets) == 52
    assert {r.status_label for r in results} == {"ONLINE", "UNSTABLE", "OFFLINE"}
    vms = [r for r in results if r.check_type == "vm" and r.status_label != "OFFLINE"]
    assert all(r.hardware and r.apps for r in vms)
    assert all(t["ip"].startswith("192.0.2.") for t in targets if t["type"] == "vm")
