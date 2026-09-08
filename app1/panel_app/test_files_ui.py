"""test_files_ui.py — the file manager's row actions must stay tappable.

Run: python app/panel_app/test_files_ui.py

A file row carries up to four actions (Edit, Startup, a package button, Delete).
They used to be bare 11px text in a 75px grid column at phone width, which is a
target a finger cannot land on while the same media block bumps every other small
control to 44px. The row now drops to a single column there and the buttons get a
real box, so this pins both halves: the desktop rule that gives them a box, and
the <=760px rule that gives them the touch target.

Text only: no panel import, so no Oracle connection.
"""

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
CSS = HERE / "static" / "app.css"
SERVER_JS = HERE / "static" / "q4.js"


def _block(css, query):
    """The body of an @media block, by its query text."""
    start = css.find(f"@media ({query})")
    assert start >= 0, f"app.css no longer has an @media ({query}) block"
    depth = 0
    for index in range(css.index("{", start), len(css)):
        if css[index] == "{":
            depth += 1
        elif css[index] == "}":
            depth -= 1
            if depth == 0:
                return css[start:index]
    raise AssertionError(f"@media ({query}) block is unterminated")


def _rule(css, selector):
    match = re.search(rf"(?m)^\s*{re.escape(selector)}\s*\{{([^}}]*)\}}", css)
    assert match, f"app.css no longer has a `{selector}` rule"
    return match.group(1)


def _px(body, prop):
    match = re.search(rf"{prop}\s*:\s*(\d+)px", body)
    return int(match.group(1)) if match else None


def main():
    css = CSS.read_text(encoding="utf-8")
    mobile = _block(css, "max-width: 760px")

    actions = _rule(css, ".file-actions button")
    assert _px(actions, "min-height"), (
        "`.file-actions button` lost its min-height: row actions are back to bare "
        "text with no hit area"
    )
    assert "padding" in actions, "`.file-actions button` lost its padding"
    # The touch-target floor the same media block enforces for every other small
    # control. Read it from `.button-small` rather than hardcoding 44, so one
    # place moves the floor.
    floor = _px(_rule(mobile, ".button-small"), "min-height")
    assert floor, "the <=760px block no longer sets a .button-small touch target"
    tapped = _px(_rule(mobile, ".file-actions button"), "min-height")
    assert tapped and tapped >= floor, (
        f"row actions are {tapped}px at phone width but every other small control "
        f"gets {floor}px"
    )

    # A fixed-width actions column is what squeezed four buttons into 75px. The
    # row has to be single-column here so they wrap onto their own line.
    # The tick column (28px) is fixed but narrow; the actions now span full width
    # below the name so four 44px buttons fit.
    row = _rule(mobile, ".file-row")
    columns = re.search(r"grid-template-columns\s*:\s*([^;]+)", row)
    assert columns, "the <=760px block no longer restates .file-row's columns"
    # The 28px tick column is allowed; what must NOT appear is a second fixed
    # column that would confine actions to a narrow cell.
    fixed = re.findall(r"(\d+)px", columns.group(1))
    assert fixed == ["28"], (
        f"`.file-row` has unexpected fixed columns at phone width: {fixed}. "
        "Only the 28px tick column should be fixed; actions must span full width."
    )
    # And the actions cell must span all columns so its buttons wrap freely.
    actions = _rule(mobile, ".file-actions")
    assert "grid-column" in actions and "1 / -1" in actions, (
        "`.file-actions` lost its full-width span at phone width"
    )

    # The rows are built with createElement; the loading/empty/error states used
    # to be innerHTML strings. Nothing in the files view should parse HTML.
    js = SERVER_JS.read_text(encoding="utf-8")
    body = js[js.index("const loadFiles ="):js.index("const setStartupFile =")]
    assert "innerHTML" not in body.replace("icon.innerHTML", ""), (
        "loadFiles is back to writing HTML strings for its states"
    )

    print(f"ok — file row actions get a box and {tapped}px targets at phone width")


if __name__ == "__main__":
    main()
