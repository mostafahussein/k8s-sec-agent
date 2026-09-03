"""Network policy coverage analysis per namespace."""

import json

from k8s_sec_agent.sanitizer import get_sanitizer
from k8s_sec_agent.tools.k8s_client import get_resources_json


async def get_network_policy_coverage() -> str:
    """Check network policy coverage per namespace.

    Identifies namespaces with no policies (default allow-all traffic).
    """
    try:
        ns_data = await get_resources_json("namespace")
        namespaces = [ns["metadata"]["name"] for ns in ns_data.get("items", [])]

        coverage = []
        for ns in namespaces:
            policies = await get_resources_json("networkpolicy", namespace=ns)
            policy_count = len(policies.get("items", []))

            pods = await get_resources_json("pod", namespace=ns)
            pod_count = len(pods.get("items", []))

            if pod_count > 0:
                coverage.append({
                    "namespace": ns,
                    "pods": pod_count,
                    "network_policies": policy_count,
                    "protected": policy_count > 0,
                })

        unprotected = [c for c in coverage if not c["protected"]]
        return get_sanitizer().sanitize(json.dumps({
            "total_namespaces_with_pods": len(coverage),
            "unprotected_namespaces": len(unprotected),
            "details": coverage,
        }, indent=2))
    except json.JSONDecodeError as e:
        return f"Error parsing network policy data: {e}"
    except Exception as e:
        return f"Error fetching network policy data: {e}"
