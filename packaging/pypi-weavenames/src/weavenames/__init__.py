"""Brandrune runs inside Claude Code. This module only prints how to install it."""

MESSAGE = """Brandrune is a Claude Code skill. Install it from inside Claude Code:

  /plugin marketplace add brandrune/brandrune
  /plugin install brandrune@brandrune

More: https://brandrune.com
"""


def main() -> int:
    print(MESSAGE, end="")
    return 0
