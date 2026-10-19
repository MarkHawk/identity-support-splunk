import io
import shutil
import stat
import subprocess

import pytest

from conftest import ROOT, load_script
from test_sender import FakeHEC
from tls_helpers import make_ca_and_server, server_context

connect = load_script("connect_local_splunk")

TOKEN = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OTHER = "11111111-2222-3333-4444-555555555555"
CREATED = f"""WARNING: Server Certificate Hostname Validation is disabled.
http://identity-support
\ttoken={TOKEN}
\tdescription=identity_support app
\tindex=identity_support
"""
LISTED = f"""http
\tport=8088
http://identity-support
\ttoken={TOKEN}
\tindex=identity_support
http://splunk_hec_token
\ttoken={OTHER}
"""


class FakeDocker:
    def __init__(self, ca, create=CREATED, create_err="", create_code=0):
        self.ca, self.calls = ca, []
        self.create, self.create_err, self.create_code = create, create_err, create_code

    def __call__(self, cmd):
        self.calls.append(cmd)
        if cmd[:2] == ["docker", "exec"] and "create" in cmd:
            return subprocess.CompletedProcess(cmd, self.create_code, self.create, self.create_err)
        if cmd[:2] == ["docker", "exec"] and "list" in cmd:
            return subprocess.CompletedProcess(cmd, 0, LISTED, "")
        if cmd[:2] == ["docker", "cp"]:
            shutil.copy(self.ca, cmd[3])
            return subprocess.CompletedProcess(cmd, 0, "", "")
        raise AssertionError(f"unexpected command {cmd}")


@pytest.fixture
def hec(tmp_path):
    paths = make_ca_and_server(tmp_path, names=("SplunkServerDefaultCert",), ips=())
    server = FakeHEC(tls=server_context(paths))
    yield server, paths
    server.close()


def run(tmp_path, hec, capfd, docker, *extra):
    server, _ = hec
    out = io.StringIO()
    code = connect.main(["--env-file", str(tmp_path / ".env"), "--ca-out", str(tmp_path / "splunk-ca.pem"),
                         "--hec-url", f"https://127.0.0.1:{server.port}", *extra], out=out, runner=docker)
    captured = capfd.readouterr()
    text = out.getvalue() + captured.out + captured.err
    assert TOKEN not in text and OTHER not in text, "a HEC token reached the output"
    return code, text


def test_success_never_prints_the_token(tmp_path, hec, capfd):
    server, paths = hec
    code, text = run(tmp_path, hec, capfd, FakeDocker(paths["ca"]))
    assert code == 0
    for n in range(1, 5):
        assert f"[{n}/4]" in text
    assert text.count("success looks like:") == 4
    assert "token created" in text and "sent " in text and "Done." in text
    # the test report reached HEC with the new token, over verified TLS
    assert server.requests[0]["headers"]["Authorization"] == f"Splunk {TOKEN}"
    assert server.requests[0]["path"] == "/services/collector/event"


def test_env_file_gets_the_settings_and_is_private(tmp_path, hec, capfd):
    server, paths = hec
    (tmp_path / ".env").write_text("# mine\nSPLUNK_PASSWORD=keep\nHEC_TOKEN=old\n")
    run(tmp_path, hec, capfd, FakeDocker(paths["ca"]))
    text = (tmp_path / ".env").read_text()
    assert text.startswith("# mine\nSPLUNK_PASSWORD=keep\n")
    assert f"HEC_TOKEN={TOKEN}\n" in text and "HEC_TOKEN=old" not in text
    assert f"HEC_URL=https://127.0.0.1:{server.port}\n" in text and "HEC_INDEX=identity_support\n" in text
    assert stat.S_IMODE((tmp_path / ".env").stat().st_mode) == 0o600


def test_new_env_file_starts_from_the_example(tmp_path, hec, capfd):
    _, paths = hec
    run(tmp_path, hec, capfd, FakeDocker(paths["ca"]))
    assert (tmp_path / ".env").read_text().startswith((ROOT / ".env.example").read_text().splitlines()[0])


def test_existing_token_is_reused_without_printing_any_token(tmp_path, hec, capfd):
    _, paths = hec
    docker = FakeDocker(paths["ca"], create="", create_err="An object with name=http://identity-support already exists",
                        create_code=22)
    code, text = run(tmp_path, hec, capfd, docker)
    assert code == 0 and "already existed, reused" in text
    assert f"HEC_TOKEN={TOKEN}\n" in (tmp_path / ".env").read_text()  # its own token, not the other one


def test_failure_message_masks_tokens(tmp_path, hec, capfd):
    _, paths = hec
    docker = FakeDocker(paths["ca"], create="", create_err=f"odd error mentioning {TOKEN}", create_code=1)
    code, text = run(tmp_path, hec, capfd, docker)
    assert code == 1 and "could not create the HEC token" in text and "<token hidden>" in text
    assert not (tmp_path / ".env").exists()


def test_commands_run_as_splunk_in_the_named_container(tmp_path, hec, capfd):
    _, paths = hec
    docker = FakeDocker(paths["ca"])
    run(tmp_path, hec, capfd, docker, "--container", "my-splunk")
    create = docker.calls[0]
    assert create[:6] == ["docker", "exec", "-u", "splunk", "my-splunk", "/opt/splunk/bin/splunk"]
    assert create[create.index("-index") + 1] == "identity_support"
    assert docker.calls[1] == ["docker", "cp", "my-splunk:/opt/splunk/etc/auth/cacert.pem",
                               str(tmp_path / "splunk-ca.pem")]
    assert all(c[:2] in (["docker", "exec"], ["docker", "cp"]) for c in docker.calls)
    assert not any(word in " ".join(c) for c in docker.calls for word in ("restart", "stop", "rm "))


def test_untrusted_hec_fails_cleanly(tmp_path, hec, capfd):
    _, paths = hec
    (tmp_path / "other").mkdir()
    other_ca = make_ca_and_server(tmp_path / "other")
    code, text = run(tmp_path, hec, capfd, FakeDocker(other_ca["ca"]))
    assert code == 1 and "not trusted" in text and "test report was not accepted" in text
