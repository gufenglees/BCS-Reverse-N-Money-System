"""
BCS CLI Package
===============
Command-line interface for BCS (Bidirectional Currency System).

Entry point: cli.main.cli

Usage::

    $ bcs wallet create --label "personal"
    $ bcs tx transfer --from <addr> --to <addr> --amount 1000000000
    $ bcs offline enable
    $ bcs gov params
"""

from cli.main import cli

__all__ = ["cli"]
