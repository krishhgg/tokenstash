#!/usr/bin/env python3
"""Rewrite a README's relative links to absolute repository URLs.

Neither npmjs.com nor pypi.org resolves a relative link, so `docs/…` and `scripts/…`
render as 404s on the package page. Markdown links and HTML href/src both.

    scripts/absolute-links.py <in.md> <out.md>
"""
import re
import sys

REPO = "https://github.com/krishhgg/tokenstash"


def absolute_links(readme, repo=REPO):
    def absolute(target):
        if re.match(r"^(https?:|mailto:|#|data:)", target):
            return target
        kind = "raw" if re.search(r"\.(png|gif|svg|jpe?g)$", target) else "blob"
        return f"{repo}/{kind}/main/{target.removeprefix('./')}"

    readme = re.sub(r"(\]\()([^)\s]+)\)", lambda m: f"{m.group(1)}{absolute(m.group(2))})", readme)
    return re.sub(r'((?:href|src)=")([^"]+)"', lambda m: f'{m.group(1)}{absolute(m.group(2))}"', readme)


if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, encoding="utf-8") as f:
        out = absolute_links(f.read())
    with open(dst, "w", encoding="utf-8") as f:
        f.write(out)
