"""Kata package."""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

try:
    __version__ = _version("kata")
except PackageNotFoundError:  # not installed (e.g. running from a source checkout)
    __version__ = "0+unknown"
