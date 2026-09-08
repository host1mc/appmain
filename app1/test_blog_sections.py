"""test_blog_sections.py — every section kind must be one blog_post.html renders.

Run: python app/test_blog_sections.py

blog_post.html has no {% else %} branch, so a section whose kind it does not know
is dropped silently: the article publishes with a paragraph missing and nothing
anywhere says so. Same for a CTA — the template indexes s[1] through s[4] and a
short tuple is a 500 on a live page. This check is the thing that notices.

Loads blog.py by path so it does not import frontend, which pulls in the
database.
"""

import importlib.util
import sys
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "_blog_under_test", Path(__file__).with_name("blog.py")
)
blog = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = blog
_spec.loader.exec_module(blog)

RENDERED_KINDS = {"h2", "h3", "p", "ul", "ol", "cta"}
LIST_KINDS = {"ul", "ol"}

# Endpoints the CTA boxes may point at, checked against frontend.py's routes and
# the panel's. A typo here is a link that 500s on a published article.
ENDPOINTS = {"panel": {"user_register"}, "site": {"help", "hosting"}}

REQUIRED_KEYS = {
    "slug", "title", "description", "date", "date_display",
    "category", "read_minutes", "sections",
}


def main():
    posts = blog.POSTS
    assert posts, "the blog has no posts"

    slugs = set()
    for post in posts:
        where = post.get("slug", "<no slug>")
        missing = REQUIRED_KEYS - set(post)
        assert not missing, f"{where}: missing {sorted(missing)}"
        assert post["slug"] not in slugs, f"duplicate slug {post['slug']}"
        slugs.add(post["slug"])
        assert post["slug"] == post["slug"].strip().lower().replace(" ", "-"), (
            f"{where}: slug is not url-shaped"
        )
        # _rfc822 in frontend.py parses this, and the feed's lastBuildDate is the
        # first one after sorting, so a malformed date breaks the whole feed.
        year, month, day = post["date"].split("-")
        assert (len(year), len(month), len(day)) == (4, 2, 2), f"{where}: bad date"
        assert blog.get_post(post["slug"]) is post, f"{where}: not findable by slug"

        for section in post["sections"]:
            kind = section[0]
            assert kind in RENDERED_KINDS, f"{where}: {kind!r} is not rendered"
            if kind in LIST_KINDS:
                assert len(section) == 2 and section[1], f"{where}: empty {kind}"
                assert all(isinstance(item, str) for item in section[1]), (
                    f"{where}: {kind} items must be strings"
                )
            elif kind == "cta":
                assert len(section) == 5, f"{where}: cta needs title, body, label, link"
                title, body, label, link = section[1:]
                assert all(isinstance(part, str) and part for part in (title, body, label)), (
                    f"{where}: cta text is empty"
                )
                target, endpoint = link
                assert endpoint in ENDPOINTS.get(target, ()), (
                    f"{where}: cta points at unknown {target} endpoint {endpoint!r}"
                )
            else:
                assert len(section) == 2 and isinstance(section[1], str) and section[1], (
                    f"{where}: {kind} has no text"
                )

    # The listing page renders in this order, so the newest article has to lead.
    dates = [post["date"] for post in blog.all_posts()]
    assert dates == sorted(dates, reverse=True), f"all_posts is not newest-first: {dates}"
    assert len(blog.all_posts()) == len(posts)

    print(f"ok — {len(posts)} posts")


if __name__ == "__main__":
    main()
