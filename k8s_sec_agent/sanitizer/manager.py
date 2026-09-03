"""SanitizerManager — multi-tenant sanitizer registry with session scoping.

Manages a registry of scoped K8sSanitizer instances. Each MCP session
gets its own sanitizer with a unique scope prefix. Tokens are globally
unique, so concurrent conversations never share or collide on mappings.

Module-level functions provide a clean public API:
    set_session()    — create a new scoped sanitizer for an MCP session
    get_sanitizer()  — get the active session's sanitizer (for tool output)
    rehydrate_all()  — rehydrate tokens from all active sanitizers
    has_mappings()   — check if any sanitizer has data
"""

import contextvars
import logging
import secrets
import threading
import time
from typing import Dict

from k8s_sec_agent.sanitizer.core import K8sSanitizer

logger = logging.getLogger(__name__)


class SanitizerManager:
    """Registry of scoped sanitizers for multi-tenant isolation.

    Each MCP session gets its own K8sSanitizer with a unique scope prefix.
    rehydrate_all() checks every active sanitizer — scope-prefixed tokens
    ensure only the correct sanitizer matches a given token.
    """

    def __init__(self, ttl_seconds: int = 300):
        self._sanitizers: Dict[str, tuple[K8sSanitizer, float]] = {}
        self._ttl = ttl_seconds
        self._lock = threading.Lock()

    def create_for_session(self) -> K8sSanitizer:
        """Create a new scoped sanitizer for an MCP session."""
        scope = secrets.token_hex(2)
        sanitizer = K8sSanitizer(scope=scope)
        with self._lock:
            self._evict_expired()
            self._sanitizers[scope] = (sanitizer, time.time())
        logger.debug("created sanitizer scope=%s (%d active)", scope, len(self._sanitizers))
        return sanitizer

    def touch(self, sanitizer: K8sSanitizer) -> None:
        """Update last-active timestamp for a sanitizer."""
        with self._lock:
            scope = sanitizer._scope
            if scope in self._sanitizers:
                self._sanitizers[scope] = (sanitizer, time.time())

    def rehydrate_all(self, text: str) -> str:
        """Rehydrate tokens from ALL active sanitizers.

        Since tokens are scope-prefixed, only the correct sanitizer
        matches a given token. Safe to apply all sanitizers.
        """
        with self._lock:
            self._evict_expired()
            all_reverse: Dict[str, str] = {}
            for sanitizer, _ in self._sanitizers.values():
                all_reverse.update(sanitizer._reverse)

        if not all_reverse:
            return text

        result = text
        for token, real in sorted(all_reverse.items(), key=lambda x: len(x[0]), reverse=True):
            result = result.replace(token, real)
        return result

    def has_mappings(self) -> bool:
        """Check if any active sanitizer has mappings."""
        with self._lock:
            return any(s._reverse for s, _ in self._sanitizers.values())

    def _evict_expired(self) -> None:
        """Remove sanitizers idle beyond TTL. Must hold self._lock."""
        now = time.time()
        expired = [
            scope for scope, (_, ts) in self._sanitizers.items()
            if (now - ts) > self._ttl
        ]
        for scope in expired:
            logger.debug("evicting sanitizer scope=%s (expired)", scope)
            del self._sanitizers[scope]


# ------------------------------------------------------------------
# Module-level singleton and public API
# ------------------------------------------------------------------

_manager: SanitizerManager | None = None

_active_sanitizer: contextvars.ContextVar[K8sSanitizer | None] = contextvars.ContextVar(
    "_active_sanitizer", default=None
)


def get_manager() -> SanitizerManager:
    """Get the global sanitizer manager."""
    global _manager
    if _manager is None:
        _manager = SanitizerManager()
    return _manager


def set_session(session_id: str) -> K8sSanitizer:
    """Create a new scoped sanitizer for an MCP session."""
    sanitizer = get_manager().create_for_session()
    _active_sanitizer.set(sanitizer)
    return sanitizer


def get_sanitizer() -> K8sSanitizer:
    """Get the active session-scoped sanitizer (for sanitize operations).

    Returns the session-scoped sanitizer if inside an MCP tool call.
    Falls back to creating a new one (should not happen in normal flow).
    """
    active = _active_sanitizer.get(None)
    if active is not None:
        get_manager().touch(active)
        return active
    return get_manager().create_for_session()


def rehydrate_all(text: str) -> str:
    """Rehydrate tokens from all active sanitizers.

    Used by the proxy (to rehydrate LLM responses) and by run_kubectl
    (to resolve tokens from previous turns before querying the cluster).
    """
    return get_manager().rehydrate_all(text)


def has_mappings() -> bool:
    """Check if any active sanitizer has mappings."""
    return get_manager().has_mappings()
