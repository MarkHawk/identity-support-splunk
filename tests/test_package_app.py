import tarfile

from conftest import load_script

package = load_script("package_app")


def test_archive_holds_the_app_and_nothing_a_running_splunk_wrote(tmp_path, monkeypatch):
    app = tmp_path / "identity_support"
    for rel in ("default/app.conf", "default/data/ui/views/v.xml", "lookups/c.csv", "metadata/default.meta",
                "metadata/local.meta", "local/props.conf", "default/__pycache__/x.pyc", "notes.txt"):
        (app / rel).parent.mkdir(parents=True, exist_ok=True)
        (app / rel).write_text("[id]\nversion = 1.2.3\n" if rel == "default/app.conf" else "x")
    monkeypatch.setattr(package, "APP", app)
    monkeypatch.setattr(package, "ROOT", tmp_path)
    out = package.build()
    assert out.name == "identity_support-1.2.3.tgz"
    with tarfile.open(out) as tar:
        names = {m.name for m in tar.getmembers() if m.isfile()}
        assert names == {"identity_support/default/app.conf", "identity_support/default/data/ui/views/v.xml",
                         "identity_support/lookups/c.csv", "identity_support/metadata/default.meta"}
        assert all(m.uname == "nobody" and m.mtime == 0 for m in tar.getmembers())


def test_same_source_gives_the_same_archive(tmp_path):
    a, b = package.build(tmp_path / "a.tgz"), package.build(tmp_path / "b.tgz")
    assert a.read_bytes() == b.read_bytes()
