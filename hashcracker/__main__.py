"""Enables ``python -m hashcracker``.

The ``if __name__ == "__main__"`` guard in the console entry point matters for
multiprocessing under the *spawn* start method (macOS/Windows): spawned workers
re-import the main module, and without a guard that would recursively launch
new pools. Routing through ``cli.main`` (which is only called here) keeps that
safe.
"""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
