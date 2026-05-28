"""Compatibility shim — delegates to the current generator CLI."""
from .sitegen.cli import main

if __name__ == "__main__":
    main()
