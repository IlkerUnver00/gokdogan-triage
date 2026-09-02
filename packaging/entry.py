"""PyInstaller entry point for the standalone gokdogan.exe.

Kept as a tiny script (rather than pointing PyInstaller at the package's
__main__) so the frozen binary has one unambiguous start-up path.
"""

import sys

from gokdogan.cli import main

if __name__ == "__main__":
    sys.exit(main())
