"""The dashboards, saved searches and app metadata hang together."""

import json
import re
import xml.etree.ElementTree as ET

import pytest

from splunk_conf import APP, read_conf

VIEWS = sorted((APP / "default/data/ui/views").glob("*.xml"))
RUNBOOK_URL = re.compile(r"https://github\.com/MarkHawk/identity-lab/(?:blob|tree)/main/runbooks\S*")


def definition(view):
    root = ET.parse(view).getroot()
    assert root.tag == "dashboard" and root.get("version") == "2", "Dashboard Studio view"
    return root, json.loads(root.findtext("definition"))


@pytest.mark.parametrize("view", VIEWS, ids=lambda p: p.stem)
def test_dashboard_studio_definition_is_consistent(view):
    root, d = definition(view)
    assert root.findtext("label") == d["title"]
    sources, vizzes = d["dataSources"], d["visualizations"]
    for name, viz in vizzes.items():
        assert viz["dataSources"]["primary"] in sources, name
    for name, source in sources.items():
        if source["type"] == "ds.chain":
            assert source["options"]["extend"] in sources, name
        else:
            assert source["type"] == "ds.search"
            # every base search reads the app's index through its macros
            assert source["options"]["query"].startswith(("`support_index`", "`support_failures`")), name
    placed = [item["item"] for item in d["layout"]["structure"]]
    assert sorted(placed) == sorted(vizzes)
    assert d["layout"]["globalInputs"] == list(d["inputs"])
    for item in d["layout"]["structure"]:
        p = item["position"]
        assert p["x"] + p["w"] <= d["layout"]["options"]["width"], item["item"]


def test_nav_lists_every_view():
    nav = ET.parse(APP / "default/data/ui/nav/default.xml").getroot()
    names = {v.get("name") for v in nav.iter("view")}
    assert {v.stem for v in VIEWS} <= names
    assert nav.find("view[@default='true']").get("name") == "support_overview"


def test_saved_searches_use_the_macros_and_name_a_runbook():
    saved = read_conf("savedsearches.conf")
    assert saved.sections()
    for name in saved.sections():
        s = saved[name]
        assert s["search"].startswith("`support_index`"), name
        assert s["enableSched"] == "1" and s["alert.track"] == "1", name
        assert "action." not in " ".join(s), f"{name}: no alert actions are shipped"
        if name != "rate-limit-probe found a problem":
            assert RUNBOOK_URL.search(s["description"]), name
            assert "runbook_url" in s["search"], name


def test_app_identity():
    app = read_conf("app.conf")
    assert app["package"]["id"] == app["id"]["name"] == "identity_support" == APP.name
    assert app["launcher"]["version"] == app["id"]["version"]
    assert set(read_conf("indexes.conf").sections()) == {"identity_support"}
    assert read_conf("macros.conf")["support_index"]["definition"] == "index=identity_support"


def test_text_is_uk_english_without_em_dashes():
    for path in APP.rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8")
            assert "—" not in text, path
            assert not re.search(r"\b(?:analyz|organiz|initializ|color\b(?!=))", text), path
