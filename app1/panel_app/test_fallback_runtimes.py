"""test_fallback_runtimes.py — the panel's cold-start runtime list must match the node's.

Run: python app/panel_app/test_fallback_runtimes.py

runtime.FALLBACK_RUNTIMES is what the deploy page renders before any catalog fetch
has landed, and the node agent's catalog.py is what the create is actually checked
against. They live in two deployments and cannot import each other, so nothing but
this check notices when a runtime or version is added on one side only — and the
symptom of drift is a version a customer can pick and the node then refuses, after
the server row exists.

Reads the constant with ast rather than importing panel_app, which resolves an
Oracle connection.
"""

import ast
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CATALOG = HERE.parents[1] / "node-agent" / "node_agent" / "catalog.py"


def _fallback():
    tree = ast.parse(HERE.joinpath("runtime.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "FALLBACK_RUNTIMES" for t in node.targets
        ):
            return ast.literal_eval(node.value)
    raise AssertionError("runtime.py no longer defines FALLBACK_RUNTIMES")


def _catalog():
    assert CATALOG.is_file(), f"the node agent's catalog is not at {CATALOG}"
    spec = importlib.util.spec_from_file_location("_catalog_under_test", CATALOG)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main():
    fallback = _fallback()
    catalog = _catalog()
    public = catalog.public_catalog()

    assert fallback == public, (
        "FALLBACK_RUNTIMES has drifted from the node agent's catalog:\n"
        f"  panel only: {sorted(set(fallback) - set(public))}\n"
        f"  node only:  {sorted(set(public) - set(fallback))}\n"
        + "\n".join(
            f"  {key}: panel {fallback[key]} != node {public[key]}"
            for key in sorted(set(fallback) & set(public))
            if fallback[key] != public[key]
        )
    )

    # Key order decides the order of the cards in the deploy page's runtime grid,
    # and dict equality above does not see it.
    assert list(fallback) == list(public), (
        f"runtime order differs: panel {list(fallback)} != node {list(public)}"
    )

    # What q3.js reads off each entry. A missing default_startup renders an
    # empty command field, which posts as a validation error the reader cannot
    # explain; a missing versions list renders an empty <select>.
    for name, entry in fallback.items():
        for key in ("label", "versions", "default_version", "default_startup"):
            assert entry.get(key), f"{name}: {key} is missing or empty"
        assert entry["default_version"] in entry["versions"], (
            f"{name}: default_version {entry['default_version']!r} is not in versions"
        )
        # resolve_image is the node's allowlist; every version offered has to pass it.
        for version in entry["versions"]:
            catalog.resolve_image(name, version)

    print(f"ok — {len(fallback)} runtimes match the node catalog")


if __name__ == "__main__":
    main()
