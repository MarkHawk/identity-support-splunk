"""Read the app's .conf files and run their regexes in Python.

Splunk's regexes are PCRE; the ones in this app only use features Python's re
also has, once named groups are spelt (?P<name>...). Calculated fields (EVAL)
need a real Splunk: see test_splunk_live.py.
"""

import configparser
import re

from conftest import ROOT

APP = ROOT / "identity_support"


def read_conf(name):
    parser = configparser.RawConfigParser(delimiters=("=",), comment_prefixes=("#",), strict=True,
                                          interpolation=None, empty_lines_in_values=False)
    parser.optionxform = str  # keys are case-sensitive
    text = (APP / "default" / name).read_text(encoding="utf-8")
    # A trailing backslash continues the value on the next line.
    parser.read_string(re.sub(r"\\\n", " ", text))
    return parser


def pcre(pattern):
    return re.compile(re.sub(r"\(\?<(?![=!])", "(?P<", pattern))


def break_events(stanza, text):
    """Split text into events the way LINE_BREAKER does: at the first group."""
    breaker = pcre(stanza["LINE_BREAKER"])
    events, start = [], 0
    for m in breaker.finditer(text):
        events.append(text[start:m.start(1)])
        start = m.end(1)
    events.append(text[start:].rstrip("\r\n"))
    return [e for e in events if e]


def extract(props_stanza, transforms, event):
    """Fields from every EXTRACT-, REPORT- and FIELDALIAS- in a props stanza,
    in Splunk's order (extractions, then aliases)."""
    fields = {}
    for key, value in props_stanza.items():
        if key.startswith("EXTRACT-"):
            m = pcre(value).search(event)
            if m:
                fields.update({k: v for k, v in m.groupdict().items() if v is not None})
        elif key.startswith("REPORT-"):
            for name in (n.strip() for n in value.split(",")):
                t = transforms[name]
                k_format, v_format = t["FORMAT"].split("::")
                # Splunk takes a field name from $n only when it is the whole
                # name: kc_$1 gives a field called kc__1, so refuse it here.
                assert k_format == "$1" or "$" not in k_format, f"{name}: prefixed dynamic field name"
                for m in pcre(t["REGEX"]).finditer(event):
                    k = re.sub(r"\$(\d)", lambda g: m.group(int(g.group(1))), k_format)
                    v = re.sub(r"\$(\d)", lambda g: m.group(int(g.group(1))), v_format)
                    fields.setdefault(k, v)
    for key, value in props_stanza.items():
        if key.startswith("FIELDALIAS-"):
            words = value.split()
            for source, as_, alias in zip(words[::3], words[1::3], words[2::3]):
                assert as_ == "AS", value
                if source in fields:
                    fields[alias] = fields[source]
    return fields
