"""General kubectl command execution via kagent-tool-server with sanitization."""

import logging
import shlex

from k8s_sec_agent.sanitizer import get_sanitizer, rehydrate_all
from k8s_sec_agent.tools.k8s_client import (
    describe_resource,
    get_pod_logs,
    get_resource_yaml,
    get_resources,
)

logger = logging.getLogger(__name__)


def _parse_kubectl_args(command: str) -> dict:
    """Parse a kubectl command string into tool server parameters.

    Returns a dict with 'action' and relevant parameters.
    Uses shlex to handle quoted arguments (e.g. custom-columns with special chars).
    """
    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()

    if not parts:
        return {"action": "get", "resource_types": ["pods"], "resource_names": []}

    action = parts[0]
    rest = parts[1:]

    # Extract flags
    namespace = None
    all_namespaces = False
    output = None
    positional = []

    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg in ("-n", "--namespace") and i + 1 < len(rest):
            namespace = rest[i + 1]
            i += 2
        elif arg in ("-A", "--all-namespaces"):
            all_namespaces = True
            i += 1
        elif arg in ("-o", "--output") and i + 1 < len(rest):
            output = rest[i + 1]
            i += 2
        elif arg.startswith("-o"):
            output = arg[2:]  # -ojson, -owide, etc.
            i += 1
        elif arg.startswith("-"):
            # Skip unknown flags and their values if applicable
            # Handle --flag=value
            if "=" in arg:
                i += 1
            # Handle --flag value (heuristic: next arg doesn't start with -)
            elif arg.startswith("--") and i + 1 < len(rest) and not rest[i + 1].startswith("-"):
                i += 2
            else:
                i += 1
        else:
            positional.append(arg)
            i += 1

    # First positional may be comma-separated resource types
    # e.g. "daemonsets,deployments,statefulsets"
    resource_types = []
    resource_names = []
    if positional:
        resource_types = positional[0].split(",")
        resource_names = positional[1:]

    return {
        "action": action,
        "resource_types": resource_types,
        "resource_names": resource_names,
        "namespace": namespace,
        "all_namespaces": all_namespaces,
        "output": output,
    }


def _normalize_output(output: str | None, has_names: bool = False) -> str:
    """Normalize output format — always use json for proper sanitization.

    The sanitizer handles JSON contextually (knows which fields are
    names, namespaces, IPs, etc.). YAML and other formats fall back to
    weak text-mode sanitization that misses most fields.
    """
    if not output or output in ("json", "wide"):
        return "json" if has_names else (output or "wide")
    # Everything else (yaml, custom-columns, jsonpath, etc.) → json
    return "json"


async def _get_resources_safe(resource_type: str, **kwargs) -> str:
    """Fetch a resource, returning an error message instead of raising."""
    try:
        return await get_resources(resource_type, **kwargs)
    except Exception as e:
        logger.warning("Failed to get %s: %s", resource_type, e)
        return f"Error fetching {resource_type}: {e}"


async def run_kubectl(command: str) -> str:
    """Run a kubectl command against the cluster.

    Translates the command to the appropriate kagent-tool-server call.
    The LLM only sees pseudonymized names (pod-1, ns-2), so we rehydrate
    the command back to real names before querying the cluster.

    Args:
        command: kubectl command without 'kubectl' prefix (e.g. 'get pods -A -o json').
    """
    try:
        # Rehydrate pseudonymized tokens back to real names so the
        # tool-server receives actual resource names.
        # Uses rehydrate_all to resolve tokens from any active scope
        # (the LLM may reference tokens from previous turns).
        sanitizer = get_sanitizer()
        command = rehydrate_all(command)
        logger.debug("run_kubectl rehydrated: %s", command)

        parsed = _parse_kubectl_args(command)
        action = parsed["action"]
        resource_types = parsed["resource_types"]
        resource_names = parsed["resource_names"]
        resource_name = resource_names[0] if resource_names else None
        namespace = parsed["namespace"]
        all_namespaces = parsed["all_namespaces"]
        has_names = len(resource_names) > 0
        output = _normalize_output(parsed.get("output"), has_names=has_names)

        if action == "get" and resource_types:
            parts = []
            if len(resource_names) > 1:
                # Multiple resource names — fetch each individually, tolerating failures
                for rt in resource_types:
                    for name in resource_names:
                        parts.append(await _get_resources_safe(
                            rt, resource_name=name,
                            namespace=namespace, output=output,
                        ))
            elif len(resource_types) > 1:
                # Multiple resource types (e.g. daemonsets,deployments)
                for rt in resource_types:
                    parts.append(await _get_resources_safe(
                        rt, resource_name=resource_name,
                        namespace=namespace, all_namespaces=all_namespaces,
                        output=output,
                    ))
            else:
                parts.append(await get_resources(
                    resource_types[0], resource_name=resource_name,
                    namespace=namespace, all_namespaces=all_namespaces,
                    output=output,
                ))
            result = "\n---\n".join(parts)

        elif action == "describe" and resource_types and resource_name:
            result = await describe_resource(
                resource_types[0], resource_name,
                namespace=namespace,
            )
        elif action == "logs" and resource_name:
            result = await get_pod_logs(
                resource_name,
                namespace=namespace or "default",
            )
        else:
            # Fallback: try get_resources
            if resource_types:
                parts = []
                for rt in resource_types:
                    parts.append(await _get_resources_safe(
                        rt, resource_name=resource_name,
                        namespace=namespace, all_namespaces=all_namespaces,
                        output=output,
                    ))
                result = "\n---\n".join(parts)
            else:
                return f"Unsupported command: kubectl {command}"

        return sanitizer.sanitize(result)
    except Exception as e:
        return f"Error running kubectl command: {e}"
