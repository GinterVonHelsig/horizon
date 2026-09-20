"""Compatibility import for the TOP-DELIVERY controller module."""

try:
    from .controller import *  # type: ignore[no-redef]
except ImportError:
    from controller import *  # type: ignore[no-redef]
