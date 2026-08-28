"""gokdogan — static PE malware triage engine.

Takes a PE file, extracts static features (hashes, imphash, entropy,
packer indicators, classified strings, import-based capabilities,
YARA matches) and produces a weighted triage verdict.
"""

__version__ = "0.1.0"
