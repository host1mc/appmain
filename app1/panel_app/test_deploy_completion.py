"""test_deploy_completion.py — the deploy modal may not open the panel early.

Run: python app/panel_app/test_deploy_completion.py

A deploy is finished only when the node actually has the container and the
dependency install is done. `status` cannot answer the first half: api_status_map
presents a container the node does not know about as running/stopped from the
recorded power intent, so a deploy whose container does not exist yet looks
exactly like a finished one. That is why the payload carries `known` and why
q3.js gates on it — waiting on `status` alone made every deploy report ready
on its first poll, seconds before anything existed.

Three files have to agree for that to hold, and nothing else notices when one
drifts. Text and ast only: no panel import, so no Oracle connection.
"""

import ast
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROUTES = HERE / "routes.py"
DEPLOY_JS = HERE / "static" / "q3.js"
NEW_SERVER = HERE / "templates" / "new_server.html"


def _status_payload_keys():
    """The keys api_status_map puts on each server in its JSON response."""
    tree = ast.parse(ROUTES.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name == "api_status_map":
            for dict_node in ast.walk(node):
                if isinstance(dict_node, ast.Dict) and any(
                    isinstance(k, ast.Constant) and k.value == "install_status" for k in dict_node.keys
                ):
                    return {k.value for k in dict_node.keys if isinstance(k, ast.Constant)}
            raise AssertionError("api_status_map no longer builds a per-server status dict")
    raise AssertionError("routes.py no longer defines api_status_map")


def _create_server_body():
    tree = ast.parse(ROUTES.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name == "create_server":
            return node
    raise AssertionError("routes.py no longer defines create_server")


def _flash_is_after_the_json_return():
    """The 'creation started' flash must be unreachable on the fetch path.

    FlashMiddleware carries a queued flash across one redirect, and q3.js only
    navigates to the panel once the node confirms the container — so a flash queued
    before the JSONResponse arrives on the panel of a server that has already
    finished building, telling the reader to wait for what they are looking at. The
    no-JS path still needs it, so this checks placement rather than absence.
    """
    create = _create_server_body()
    json_returns = [
        node.lineno
        for node in ast.walk(create)
        if isinstance(node, ast.Return)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "JSONResponse"
    ]
    assert json_returns, "create_server no longer answers the fetch path with JSONResponse"
    for node in ast.walk(create):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "flash"
            and node.args
            and isinstance(node.args[-1], ast.Constant)
            and node.args[-1].value == "success"
        ):
            assert node.lineno > max(json_returns), (
                "create_server queues its success flash at line "
                f"{node.lineno}, before the JSONResponse at {max(json_returns)}: the "
                "fetch path would carry it onto the finished server's panel"
            )


def main():
    keys = _status_payload_keys()
    assert "known" in keys, (
        "api_status_map stopped sending `known`; q3.js cannot tell a container "
        f"that does not exist yet from a finished one. Sends: {sorted(keys)}"
    )
    assert {"status", "install_status"} <= keys, f"status payload lost a key: {sorted(keys)}"
    _flash_is_after_the_json_return()

    js = DEPLOY_JS.read_text(encoding="utf-8")
    assert "info.known" in js, "q3.js no longer gates completion on `known`"
    # The wait condition and the navigation, in that order: the poll must return to
    # waiting while either half is unmet, and only then open the panel.
    wait_at = js.find("if (!info.known || install === 'running') return again(")
    open_at = js.find("window.location.assign(serverUrl)", wait_at + 1 if wait_at >= 0 else 0)
    assert wait_at >= 0, "q3.js's wait-while-creating condition is gone or was reworded"
    assert open_at > wait_at, "q3.js opens the panel without waiting on the poll verdict first"

    # A link the reader can click is a way into the panel that skips the poll
    # entirely, which is the whole defect: the button was live while the container
    # was still being built.
    for path, text in (("q3.js", js), ("new_server.html", NEW_SERVER.read_text(encoding="utf-8"))):
        assert "deploy-go-server" not in text, (
            f"{path} brought back the 'Go to server' control, which opens the panel "
            "before the deploy has confirmed"
        )

    print("ok — deploy completion is gated on `known` + install_status")

if __name__ == "__main__":
    main()
