"""dog: dig + ipinfo.io in one command."""

import sys


def main() -> None:
    from .cli import main as cli_main

    sys.exit(cli_main())
