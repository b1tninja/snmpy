"""Package-root entry: ``python -m`` when the repo root is on sys.path.

Prefer ``python -m snmpy`` or the ``snmpy`` console script after install.
"""

from snmpy.cli import main

if __name__ == "__main__":
    main()
