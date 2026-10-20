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
            base = sources[source["options"]["extend"]]
            if base["type"] == "ds.search":
                # a chain only sees the fields its base search names
                assert "| fields " in base["options"]["query"] or "| stats " in base["options"]["query"], name
        else:
            assert source["type"] == "ds.search"
            # every base search reads the app's index through its macros
            assert source["options"]["query"].lstrip("(").startswith(("`support_index`", "`support_failures`")), name
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


@pytest.mark.parametrize("view", VIEWS, ids=lambda p: p.stem)
def test_default_time_range_is_last_4_hours(view):
    _, d = definition(view)
    assert d["inputs"]["input_time"]["options"]["defaultValue"] == "-4h,now"


def test_overview_charts_use_the_adaptive_bucket_macro():
    _, d = definition(APP / "default/data/ui/views/support_overview.xml")
    queries = {name: s["options"]["query"] for name, s in d["dataSources"].items()}
    assert "`support_chart(cause)`" in queries["ds_over_time"]
    assert "`support_chart(outcome)`" in queries["ds_radius"]
    assert "`support_chart(response)`" in queries["ds_proxy_status"]
    assert not any("timechart" in q for q in queries.values())
    assert "support_chart(1)" in read_conf("macros.conf")


@pytest.mark.parametrize("view", VIEWS, ids=lambda p: p.stem)
def test_runbook_drilldowns_open_a_real_url(view):
    """Splunk URL-encodes a token in a custom drilldown URL unless it has the
    |n filter, and then refuses the encoded https%3A%2F%2F... as invalid. The
    URL travels in a hidden _runbook_url field, so the table stays narrow."""
    _, d = definition(view)
    for name, viz in d["visualizations"].items():
        for handler in viz.get("eventHandlers", []):
            if handler["type"] != "drilldown.customUrl":
                continue
            assert handler["options"]["url"] == "$row._runbook_url.value|n$", name
            assert viz["options"]["showInternalFields"] is False, name
            source = d["dataSources"][viz["dataSources"]["primary"]]
            assert "_runbook_url" in source["options"]["query"].rsplit("| table ", 1)[-1], name


@pytest.mark.parametrize("view", VIEWS, ids=lambda p: p.stem)
def test_times_follow_the_viewers_time_zone(view):
    """Every time shown goes through strftime without a zone (or is _time on
    a chart axis), so each viewer sees their own Splunk time zone. No query
    names a zone, and no table shows raw _time (Studio formats that itself,
    with the zone the session started with)."""
    _, d = definition(view)
    for name, source in d["dataSources"].items():
        query = source["options"]["query"]
        assert not re.search(r"UTC|GMT|%Z|%z|[+-]00:?00", query), name
        for fmt in re.findall(r'strftime\([^,]+, "([^"]*)"\)', query):
            assert fmt == "%Y-%m-%d %H:%M:%S", (name, fmt)
        table = re.search(r"\| table ([^|]*)", query)
        if table:
            assert "_time" not in table.group(1).split(), name


def test_radius_chart_counts_in_whole_numbers():
    _, d = definition(APP / "default/data/ui/views/support_overview.xml")
    assert d["visualizations"]["viz_radius"]["options"]["yAxisMajorTickInterval"] == 1


def test_overview_layout_has_no_gaps_or_overlaps():
    """Panels tile the canvas exactly: each block is either beside or below
    another, and the canvas ends where the lowest block does."""
    _, d = definition(APP / "default/data/ui/views/support_overview.xml")
    blocks = [i["position"] for i in d["layout"]["structure"]]
    width, height = d["layout"]["options"]["width"], d["layout"]["options"]["height"]
    covered = set()
    for p in blocks:
        cells = {(x, y) for x in range(p["x"], p["x"] + p["w"], 8) for y in range(p["y"], p["y"] + p["h"], 8)}
        assert not cells & covered, p
        covered |= cells
    assert len(covered) == (width // 8) * (height // 8)


def test_proxy_panels():
    _, d = definition(APP / "default/data/ui/views/support_overview.xml")
    assert "eventtype=idlab_proxy_error" in d["dataSources"]["ds_proxy_causes"]["options"]["query"]
    colours = d["visualizations"]["viz_proxy_status"]["options"]["seriesColorsByField"]
    assert {"429", "502", "504"} <= set(colours)
    assert "eventtype=idlab_proxy_error" in read_conf("macros.conf")["support_failures"]["definition"]
