"""Splice each package README.md into its generated Hugo landing page.

Modo generates a bare `_index.md` per package (just the API listing), and the
`__init__.mojo` files carry no module docstring. This inserts each package's
`README.md` at the top of its generated landing page, right after the Hugo
front matter, so the README becomes the package's main content followed by the
auto-generated API listing.

Run from the repo root after `modo build` (see `modo.yaml` post-build).
"""

import glob
import os
import re

CONTENT_ROOT = "docs/site/content"


def main() -> None:
    for readme in glob.glob("mojo_crypto/**/README.md", recursive=True):
        index = os.path.join(CONTENT_ROOT, os.path.dirname(readme), "_index.md")
        if not os.path.isfile(index):
            continue
        doc = open(index).read()
        body = open(readme).read().strip()
        # Insert the README body right after the front-matter block.
        m = re.match(r"^(---\n.*?\n---\n)", doc, re.S)
        if m:
            doc = m.group(1) + "\n" + body + "\n\n" + doc[m.end() :]
        else:
            doc = body + "\n\n" + doc
        open(index, "w").write(doc)
        print("  +", index)


if __name__ == "__main__":
    main()
