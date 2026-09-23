"""
Re-export packet-signature detectors for backend packaging and Docker
standalone environments. Canonical implementation is in capture/signatures.py.
"""
try:
    from capture.signatures import detect_heartbleed
except ImportError:
    import os
    import sys
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
    from capture.signatures import detect_heartbleed

__all__ = ["detect_heartbleed"]
