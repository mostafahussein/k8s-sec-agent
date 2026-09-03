"""Multi-tenant K8s data sanitizer — pseudonymize identity, keep configuration."""

from k8s_sec_agent.sanitizer.core import K8sSanitizer
from k8s_sec_agent.sanitizer.manager import (
    SanitizerManager,
    get_manager,
    get_sanitizer,
    has_mappings,
    rehydrate_all,
    set_session,
)

__all__ = [
    "K8sSanitizer",
    "SanitizerManager",
    "get_manager",
    "get_sanitizer",
    "has_mappings",
    "rehydrate_all",
    "set_session",
]
