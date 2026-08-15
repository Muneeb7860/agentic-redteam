"""Pin the self-describing numbers so they cannot drift silently.

Both of these shipped WRONG in 1.1.0's tree and were caught only by a
clean-room install before upload:

  * `--version` printed "agentic-redteam 1.0.0" from a 1.1.0 package, and
    sarif_exporter.TOOL_VERSION was the literal "1.0.0" -- so every SARIF
    file would have misattributed its findings to the previous release in
    GitHub Code Scanning.
  * The package docstring advertised "114 payloads across 8 categories"
    when the package shipped 136 across 12.

A literal is fine until the thing it describes changes. These assertions are
what make that change loud.
"""
import glob
import os
import re

import yaml

import agentic_redteam
from agentic_redteam import __version__
from agentic_redteam.sarif_exporter import TOOL_VERSION

PAYLOAD_DIR = os.path.join(os.path.dirname(agentic_redteam.__file__), "payloads")


def _counts():
    files = sorted(glob.glob(os.path.join(PAYLOAD_DIR, "*.yaml")))
    total = 0
    for f in files:
        with open(f) as fh:
            data = yaml.safe_load(fh)
        if isinstance(data, list):
            total += len(data)
    return total, len(files)


def test_sarif_tool_version_tracks_package_version():
    assert TOOL_VERSION == __version__


def test_pyproject_version_matches_package_version():
    root = os.path.dirname(os.path.dirname(os.path.abspath(agentic_redteam.__file__)))
    path = os.path.join(root, "pyproject.toml")
    if not os.path.exists(path):        # installed wheel, no source tree
        return
    with open(path) as fh:
        declared = re.search(r'^version\s*=\s*"([^"]+)"', fh.read(), re.M)
    assert declared and declared.group(1) == __version__


def test_docstring_counts_match_the_shipped_payloads():
    total, categories = _counts()
    doc = agentic_redteam.__doc__ or ""
    claimed = re.search(r"(\d+)\s+payloads across\s+(\d+)\s+OWASP", doc)
    assert claimed, "package docstring no longer states its payload/category counts"
    assert int(claimed.group(1)) == total, f"docstring says {claimed.group(1)}, shipped {total}"
    assert int(claimed.group(2)) == categories, f"docstring says {claimed.group(2)}, shipped {categories}"


def test_no_literal_previous_version_remains_in_source():
    """The specific failure: a hardcoded version string left behind at bump."""
    pkg = os.path.dirname(os.path.abspath(agentic_redteam.__file__))
    offenders = []
    for path in glob.glob(os.path.join(pkg, "**", "*.py"), recursive=True):
        src = open(path).read()
        with open(path) as fh:
            for i, line in enumerate(fh, 1):
                if line.lstrip().startswith("#"):
                    continue
                if "__version__" in line:
                    continue
                # Independently versioned artifacts that must NOT track the
                # package version. Named explicitly so adding a third one is a
                # deliberate act, not a silent widening of the check.
                if "SARIF_VERSION" in line:      # the SARIF spec version
                    continue
                if "protocolVersion" in line:    # the MCP wire protocol version
                    continue
                if "class PatchConfig" in src or "version: str" in line:
                    continue                     # patch-config schema version
                if re.search(r'["\']v?\d+\.\d+\.\d+["\']', line):
                    offenders.append(f"{os.path.basename(path)}:{i}: {line.strip()}")
    assert not offenders, "hardcoded version literals found:\n" + "\n".join(offenders)
