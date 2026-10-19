"""The workflow and the reviewer stack keep their promises: least privilege,
actions pinned to SHAs, images pinned by digest, and no forbidden ports."""

import re

from conftest import ROOT

WORKFLOW = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
COMPOSE = (ROOT / "compose.yaml").read_text()


def test_actions_are_pinned_to_full_shas():
    uses = re.findall(r"uses:\s*(\S+)", WORKFLOW)
    assert uses
    for ref in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), ref


def test_read_only_token_and_ubuntu():
    assert "permissions:\n  contents: read" in WORKFLOW
    assert set(re.findall(r"runs-on:\s*(\S+)", WORKFLOW)) == {"ubuntu-latest"}


def test_compose_images_are_pinned_by_digest():
    images = re.findall(r"image:\s*(\S+)", COMPOSE)
    assert images
    for image in images:
        assert re.fullmatch(r"[\w./-]+:[\w.-]+@sha256:[0-9a-f]{64}", image), image
        assert ":latest" not in image
    assert any(i.startswith("splunk/splunk:10.4.4@") for i in images)


def test_compose_ports_are_loopback_and_allowed():
    ports = re.findall(r'-\s*"([\d.]+):(\d+):(\d+)"', COMPOSE)
    assert ports
    for host_ip, host_port, _ in ports:
        assert host_ip == "127.0.0.1"
        port = int(host_port)
        assert port != 8080 and not 8180 <= port <= 8189, port


def test_compose_accepts_the_licence_terms_10x_requires():
    assert "SPLUNK_START_ARGS: --accept-license" in COMPOSE
    assert "SPLUNK_GENERAL_TERMS: --accept-sgt-current-at-splunk-com" in COMPOSE


def test_compose_needs_secrets_from_env_and_holds_none():
    assert "${SPLUNK_PASSWORD:?" in COMPOSE and "${DEMO_HEC_TOKEN:?" in COMPOSE
    assert not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", COMPOSE)
