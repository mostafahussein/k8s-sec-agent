"""K8sSanitizer — pseudonymize Kubernetes identity data.

Replaces namespace names, pod names, service account names, IP addresses,
and secret names with scope-prefixed tokens. Security context, RBAC rules,
resource limits, and other configuration fields are kept as-is.
"""

import json
import logging
import re
from typing import Dict

logger = logging.getLogger(__name__)

# JSON keys whose values are configuration the LLM needs to analyze.
# These are recursively sanitized (sub-fields may contain identity data)
# but the key names themselves are preserved.
_CONFIG_KEYS = frozenset({
    "securityContext", "resources", "limits", "requests",
    "privileged", "runAsUser", "runAsNonRoot", "runAsGroup",
    "readOnlyRootFilesystem", "allowPrivilegeEscalation",
    "capabilities", "rules", "verbs", "apiGroups",
    "roleRef", "resourceNames",
})

# JSON keys that contain IP addresses.
_IP_KEYS = frozenset({
    "clusterIP", "podIP", "hostIP", "ip", "externalIP",
})

# System namespaces to keep as-is (LLM needs to know kube-system vs user namespace).
_KEEP_NAMESPACES = frozenset({
    "kube-system", "kube-public", "kube-node-lease",
    "default", "kagent",
})

# Regex patterns for scrubbing sensitive values in free-text strings.
_UUID_RE = re.compile(
    r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
    re.IGNORECASE,
)
_NODE_LABEL_RE = re.compile(
    r'doks\.digitalocean\.com/[a-z-]+=[\w.:/-]+'
)
_IP_RE = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')


class K8sSanitizer:
    """Pseudonymize Kubernetes identity data, preserve configuration.

    Each instance has a unique scope prefix so tokens are globally unique
    across concurrent conversations (e.g., ns-a3f2-1 vs ns-b7c8-1).
    """

    def __init__(self, scope: str):
        self._scope = scope
        self._map: Dict[str, str] = {}
        self._reverse: Dict[str, str] = {}
        self._counters = {
            "ns": 0, "pod": 0, "sa": 0, "secret": 0,
            "ip": 0, "node": 0, "user": 0, "binding": 0, "container": 0,
        }
        self._image_counter = 0

    # ------------------------------------------------------------------
    # Token generation
    # ------------------------------------------------------------------

    def _get_token(self, category: str, value: str) -> str:
        """Get or create a pseudonym token for a value."""
        if value in self._map:
            return self._map[value]
        self._counters[category] += 1
        token = f"{category}-{self._scope}-{self._counters[category]}"
        self._map[value] = token
        self._reverse[token] = value
        return token

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def sanitize(self, text: str) -> str:
        """Sanitize kubectl output — replace identity, keep config."""
        if not text:
            return text
        try:
            data = json.loads(text)
            sanitized = self._sanitize_json(data)
            result = json.dumps(sanitized, indent=2)
            logger.debug("sanitize [%s]: %d mappings active", self._scope, len(self._map))
            return result
        except (json.JSONDecodeError, TypeError):
            pass
        result = self._sanitize_text(text)
        logger.debug("sanitize (text) [%s]: %d mappings active", self._scope, len(self._map))
        return result

    def sanitize_container_name(self, name: str) -> str:
        """Pseudonymize a container name."""
        if not name:
            return name
        return self._get_token("container", name)

    def rehydrate(self, text: str) -> str:
        """Replace all tokens back to real values."""
        result = text
        for token, real in sorted(self._reverse.items(), key=lambda x: len(x[0]), reverse=True):
            result = result.replace(token, real)
        return result

    @property
    def mapping(self) -> Dict[str, str]:
        """Return the current pseudonym mapping for debugging."""
        return dict(self._map)

    # ------------------------------------------------------------------
    # JSON sanitization
    # ------------------------------------------------------------------

    def _sanitize_json(self, data):
        """Recursively sanitize JSON kubectl output."""
        if isinstance(data, dict):
            return self._sanitize_dict(data)
        if isinstance(data, list):
            return [self._sanitize_json(item) for item in data]
        if isinstance(data, str):
            return self._scrub_string(data)
        return data

    def _sanitize_dict(self, data: dict) -> dict:
        result = {}
        for key, value in data.items():
            if key == "namespace":
                result[key] = self._sanitize_namespace(value)
            elif key == "name" and isinstance(value, str):
                result[key] = self._sanitize_name(value, data)
            elif key == "pod" and isinstance(value, str):
                result[key] = self._get_token("pod", value)
            elif key == "binding" and isinstance(value, str):
                result[key] = self._get_token("binding", value)
            elif key == "nodeName":
                result[key] = self._get_token("node", value) if value else value
            elif key in ("serviceAccountName", "serviceAccount"):
                result[key] = self._get_token("sa", value) if value else value
            elif key in _IP_KEYS:
                result[key] = self._get_token("ip", value) if value else value
            elif key == "image" and isinstance(value, str):
                result[key] = self._sanitize_image(value)
            elif key == "subjects" and isinstance(value, list):
                result[key] = [self._sanitize_subject(s) for s in value]
            else:
                result[key] = self._sanitize_json(value)
        return result

    # ------------------------------------------------------------------
    # Field-level sanitizers
    # ------------------------------------------------------------------

    def _sanitize_namespace(self, ns: str) -> str:
        if not ns:
            return ns
        if ns in _KEEP_NAMESPACES:
            return ns
        return self._get_token("ns", ns)

    def _sanitize_name(self, name: str, context: dict) -> str:
        """Sanitize a name field based on what kind of resource it is."""
        if not name:
            return name
        if context.get("kind") == "Secret" or "secret" in str(context.get("type", "")).lower():
            return self._get_token("secret", name)
        return self._get_token("pod", name)

    def _sanitize_image(self, image: str) -> str:
        """Replace entire image string with a token."""
        if not image:
            return image
        if image in self._map:
            return self._map[image]
        self._image_counter += 1
        token = f"image-{self._scope}-{self._image_counter}"
        self._map[image] = token
        self._reverse[token] = image
        return token

    def _sanitize_subject(self, subject: dict) -> dict:
        """Sanitize RBAC subject — keep kind and role info."""
        result = dict(subject)
        if result.get("name"):
            kind = result.get("kind", "")
            if kind == "ServiceAccount":
                result["name"] = self._get_token("sa", result["name"])
            elif kind in ("User", "Group"):
                result["name"] = self._get_token("user", result["name"])
            if result.get("namespace"):
                result["namespace"] = self._sanitize_namespace(result["namespace"])
        return result

    # ------------------------------------------------------------------
    # String-level sanitizers
    # ------------------------------------------------------------------

    def _sanitize_ip_in_string(self, text: str) -> str:
        """Replace IP addresses in a string."""
        def replace_ip(match):
            ip = match.group(0)
            if ip.startswith("127.") or ip == "0.0.0.0":
                return ip
            return self._get_token("ip", ip)
        return _IP_RE.sub(replace_ip, text)

    def _scrub_string(self, text: str) -> str:
        """Scrub IPs, UUIDs, and cloud-provider labels from a string."""
        result = self._sanitize_ip_in_string(text)
        result = _UUID_RE.sub("<redacted-uuid>", result)
        result = _NODE_LABEL_RE.sub("<redacted-label>", result)
        return result

    def _sanitize_text(self, text: str) -> str:
        """Sanitize plain text output (non-JSON).

        Replaces IPs and any previously-mapped values so text-mode
        kubectl output is consistent with JSON-mode sanitization.
        """
        result = self._sanitize_ip_in_string(text)
        for real, token in sorted(self._map.items(), key=lambda x: len(x[0]), reverse=True):
            result = result.replace(real, token)
        return result
