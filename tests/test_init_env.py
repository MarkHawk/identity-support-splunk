import io
import shutil
import stat
import uuid

from conftest import ROOT, load_script

init_env = load_script("init_env")


def read_env(path):
    return dict(line.split("=", 1) for line in path.read_text().splitlines() if "=" in line and not line.startswith("#"))


def run(tmp_path):
    out = io.StringIO()
    assert init_env.main(tmp_path, out=out) == 0
    return out.getvalue()


def test_creates_env_from_example_and_prints_no_values(tmp_path):
    shutil.copy(ROOT / ".env.example", tmp_path / ".env.example")
    text = run(tmp_path)
    env = read_env(tmp_path / ".env")
    assert len(env["SPLUNK_PASSWORD"]) >= 20
    uuid.UUID(env["DEMO_HEC_TOKEN"])
    assert env["HEC_TOKEN"] == env["DEMO_HEC_TOKEN"] and env["HEC_URL"] == "https://127.0.0.1:18088"
    assert env["HEC_INDEX"] == "identity_support"
    for value in (env["SPLUNK_PASSWORD"], env["DEMO_HEC_TOKEN"]):
        assert value not in text
    assert stat.S_IMODE((tmp_path / ".env").stat().st_mode) == 0o600
    # comments from the example survive
    assert (tmp_path / ".env").read_text().startswith("# Copy to .env")


def test_never_changes_existing_values(tmp_path):
    (tmp_path / ".env").write_text("SPLUNK_PASSWORD=mine-already\nHEC_URL=https://splunk.example.net:8088\nHEC_TOKEN=x\n")
    text = run(tmp_path)
    env = read_env(tmp_path / ".env")
    assert env["SPLUNK_PASSWORD"] == "mine-already"
    assert env["HEC_URL"] == "https://splunk.example.net:8088" and env["HEC_TOKEN"] == "x"
    assert "set DEMO_HEC_TOKEN " in text
    assert run(tmp_path).startswith("init_env: .env already complete")
