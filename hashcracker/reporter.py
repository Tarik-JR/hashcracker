"""Live progress display: attempts, hashes/second, %, and ETA.

Two small but deliberate choices:

* **Progress goes to stderr, the result goes to stdout.** That separation is a
  Unix good-manners thing: you can capture the cracked password cleanly with
  ``pw=$(hashcracker ...)`` while the spinning progress line still shows up on
  your terminal and doesn't pollute the captured value.

* **Updates are throttled.** Redrawing on every finished batch would flood the
  terminal and actually slow things down. We repaint at most every
  ``interval`` seconds using a carriage return (``\r``) to overwrite the line
  in place, so you get a smooth live counter instead of a scrolling wall.
"""

from __future__ import annotations

import sys
import time


def _human_rate(rate: float) -> str:
    """Format a hashes/second figure with a sensible unit."""
    for unit in ("", "K", "M", "G"):
        if rate < 1000:
            return f"{rate:6.1f} {unit}H/s"
        rate /= 1000
    return f"{rate:6.1f} TH/s"


class Reporter:
    """Renders a one-line, self-overwriting progress indicator on stderr."""

    def __init__(self, total: int | None = None, *, enabled: bool = True,
                 interval: float = 0.1, stream=sys.stderr) -> None:
        self.total = total          # total candidates, if known (for % and ETA)
        self.enabled = enabled      # False under --quiet
        self.interval = interval    # min seconds between repaints
        self.stream = stream
        self._last_paint = 0.0

    def update(self, tried: int, elapsed: float) -> None:
        """Maybe repaint the progress line (throttled to ``interval``)."""
        if not self.enabled:
            return
        now = time.perf_counter()
        if now - self._last_paint < self.interval:
            return
        self._last_paint = now
        self._paint(tried, elapsed)

    def finish(self, found: str | None, tried: int, elapsed: float) -> None:
        """Paint one final line and move off it with a newline."""
        if not self.enabled:
            return
        self._paint(tried, elapsed)
        self.stream.write("\n")
        self.stream.flush()

    def _paint(self, tried: int, elapsed: float) -> None:
        rate = tried / elapsed if elapsed > 0 else 0.0
        parts = [f"{tried:>15,d} tried", _human_rate(rate), f"{elapsed:6.1f}s"]
        if self.total:
            pct = 100.0 * tried / self.total
            parts.append(f"{pct:5.1f}%")
            if rate > 0 and tried < self.total:
                eta = (self.total - tried) / rate
                parts.append(f"ETA {eta:6.1f}s")
        # '\r' returns to column 0; trailing spaces erase any leftover chars
        # from a previously longer line.
        self.stream.write("\r" + "  |  ".join(parts) + "    ")
        self.stream.flush()
