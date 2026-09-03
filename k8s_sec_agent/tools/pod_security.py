"""Pod security context analysis across all namespaces."""

import json

from k8s_sec_agent.sanitizer import get_sanitizer
from k8s_sec_agent.tools.k8s_client import get_resources_json

MAX_FINDINGS = 50


def _check_container(container: dict, sanitizer) -> list[str]:
    """Check a single container spec for security issues."""
    issues = []
    raw_name = container.get("name", "unknown")
    name = sanitizer.sanitize_container_name(raw_name)
    sc = container.get("securityContext", {})

    if sc.get("privileged"):
        issues.append(f"container '{name}' is privileged")
    if sc.get("runAsUser") == 0 or (not sc.get("runAsNonRoot") and not sc.get("runAsUser")):
        issues.append(f"container '{name}' may run as root")
    if not container.get("resources", {}).get("limits"):
        issues.append(f"container '{name}' has no resource limits")
    if not sc.get("readOnlyRootFilesystem"):
        issues.append(f"container '{name}' has writable root filesystem")

    return issues


async def get_pod_security_summary() -> str:
    """Scan all pods for security issues.

    Checks for privileged containers, root execution, missing resource
    limits, and writable root filesystems.
    """
    try:
        sanitizer = get_sanitizer()
        pods = await get_resources_json("pod", all_namespaces=True)
        issues = []

        for pod in pods.get("items", []):
            pod_issues = []
            for container in pod["spec"].get("containers", []):
                pod_issues.extend(_check_container(container, sanitizer))

            if pod_issues:
                issues.append({
                    "namespace": pod["metadata"]["namespace"],
                    "pod": pod["metadata"]["name"],
                    "issues": pod_issues,
                })

        return get_sanitizer().sanitize(
            json.dumps({"total_pods_with_issues": len(issues), "findings": issues[:MAX_FINDINGS]}, indent=2)
        )
    except json.JSONDecodeError as e:
        return f"Error parsing pod data: {e}"
    except Exception as e:
        return f"Error fetching pod security data: {e}"
