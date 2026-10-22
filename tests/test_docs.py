"""The README matches what the repository actually does."""

import re

from conftest import ROOT

README = (ROOT / "README.md").read_text()
COMPOSE = (ROOT / "compose.yaml").read_text()


def test_no_em_dashes_anywhere_in_the_docs():
    for path in [ROOT / "README.md", *ROOT.glob("docs/*.md")]:
        assert "—" not in path.read_text(), path


def test_try_it_section_and_steps():
    assert "## Try it in 5 minutes" in README
    for step in ("python3 scripts/init_env.py", "docker compose up -d", "http://localhost:18000"):
        assert step in README, step


def test_readme_ports_and_version_match_compose():
    published = set(re.findall(r'"127\.0\.0\.1:(\d+):\d+"', COMPOSE))
    assert published == {"18000", "18088", "18089"}
    for port in published:
        assert port in README, port
    version = re.search(r"splunk/splunk:([\d.]+)@", COMPOSE).group(1)
    assert f"Splunk Enterprise {version}" in README


def test_related_tools_are_linked():
    for repo in ("identity-lab", "token-inspector", "rate-limit-probe"):
        assert f"https://github.com/MarkHawk/{repo}" in README, repo
    assert "Claude Code" in README


def test_clone_url_uses_the_repository_name():
    assert "git clone https://github.com/MarkHawk/identity-support-splunk\ncd identity-support-splunk\n" in README


def test_screenshots_exist_and_come_before_try_it():
    shots = ["overview.png", "when-did-it-start.png", "who-is-affected.png", "proxy.png", "egress-proxy.png", "api.png"]
    for name in shots:
        assert (ROOT / "docs/screenshots" / name).is_file(), name
        assert f"](docs/screenshots/{name})" in README, name
    assert README.index("docs/screenshots/") < README.index("## Try it in 5 minutes")
    assert "Splunk user's time zone" in README and "times are UTC" not in README
