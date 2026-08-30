"""Compatibility shim — delegates to the current generator CLI."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from generator.sitegen.cli import main

if __name__ == "__main__":
    main()
