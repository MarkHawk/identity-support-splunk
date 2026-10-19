"""Nothing private is committed: no private IPv4 addresses, no home
directories other than /home/pi, no personal email addresses, no private
keys, no personal strings from the local .personal-patterns file (absent in
CI), and no key or certificate files at all. Checks tracked files and new
files git would add, so the sanitised samples are covered too."""

import re
import subprocess

import pytest

from conftest import ROOT, load_script

sanitise = load_script("sanitise")

# Public GitHub URLs name the account that hosts the repo; that is expected.
GITHUB_ACCOUNT = re.compile(r"github\.com/[A-Za-z0-9-]+")
# The licence names its copyright holder by design.
PERSONAL_EXEMPT = {"LICENSE"}


def repo_files():
    try:
        out = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    return [ROOT / line for line in out.splitlines() if line and (ROOT / line).is_file()]


def test_no_private_addresses_paths_emails_or_keys():
    problems = []
    for path in repo_files():
        text = path.read_bytes().decode("utf-8", errors="replace")
        for view in sanitise.decoded_views(text):
            for kind in sanitise.find_problems(view):
                problems.append(f"{path.relative_to(ROOT)}: {kind}")
    assert not sorted(set(problems))


def test_no_personal_patterns():
    personal = sanitise.load_personal_patterns(ROOT / ".personal-patterns")
    if not personal:
        return  # no local file, as in CI: nothing extra to check
    problems = []
    for path in repo_files():
        if path.name in PERSONAL_EXEMPT:
            continue
        text = GITHUB_ACCOUNT.sub("github.com/ACCOUNT", path.read_bytes().decode("utf-8", errors="replace"))
        if any(p.search(view) for view in sanitise.decoded_views(text) for p in personal):
            problems.append(str(path.relative_to(ROOT)))
    assert not problems, f"personal patterns found in: {problems}"


def test_no_key_or_certificate_files():
    """The HTTPS sender tests make their CA in a temporary directory; none is ever committed."""
    offenders = [
        p.relative_to(ROOT).as_posix() for p in repo_files()
        if p.suffix in (".pem", ".key", ".crt", ".p12", ".pfx")
    ]
    assert not offenders


def test_personal_patterns_file_is_ignored_and_example_is_empty():
    ignored = subprocess.run(["git", "check-ignore", "-q", ".personal-patterns"], cwd=ROOT, check=False)
    assert ignored.returncode == 0
    assert (ROOT / ".personal-patterns.example").read_text() == ""


@pytest.mark.parametrize("path", [".env", "captures/raw/keycloak.log"])
def test_secrets_and_raw_captures_are_ignored(path):
    ignored = subprocess.run(["git", "check-ignore", "-q", path], cwd=ROOT, check=False)
    assert ignored.returncode == 0, path


def test_env_example_has_only_empty_secrets():
    for line in (ROOT / ".env.example").read_text().splitlines():
        if line.startswith(("HEC_TOKEN=", "SPLUNK_PASSWORD=", "DEMO_HEC_TOKEN=")):
            assert line.endswith("="), line
