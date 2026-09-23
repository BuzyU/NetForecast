"""
Re-export FlowState for backend packaging and Docker standalone environments.
Canonical implementation is in capture/flow_state.py.
"""
try:
    from capture.flow_state import FlowState
except ImportError:
    import os
    import sys
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))
    from capture.flow_state import FlowState

__all__ = ["FlowState"]
