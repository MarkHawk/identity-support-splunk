import importlib.util
import ipaddress
import pathlib
import socket

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_real_getaddrinfo = socket.getaddrinfo


def load_module(path, name=None):
    """Import a .py file that is not in a package, such as scripts/sanitise.py."""
    path = ROOT / path
    spec = importlib.util.spec_from_file_location(name or path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_script(name):
    """Import one of the scripts/ files as a module."""
    return load_module(f"scripts/{name}.py", name)


def is_loopback(host):
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Tests may talk to a fake HEC on loopback, and nothing else: a name
    lookup or connection to any other address fails the test."""

    def guarded_connect(real):
        def connect(self, address):
            host = address[0] if isinstance(address, tuple) else None
            if host is None or not is_loopback(host):
                raise AssertionError(f"test attempted a non-loopback connection to {address!r}")
            return real(self, address)

        return connect

    def getaddrinfo(host, *args, **kwargs):
        if host is not None and not is_loopback(str(host)):
            raise AssertionError(f"test attempted to resolve {host!r}")
        return _real_getaddrinfo(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect(_real_connect))
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect(_real_connect_ex))
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
