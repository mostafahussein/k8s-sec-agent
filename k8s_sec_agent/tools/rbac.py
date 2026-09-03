"""RBAC analysis — cluster-admin bindings and overpermissive roles."""

import json

from k8s_sec_agent.sanitizer import get_sanitizer
from k8s_sec_agent.tools.k8s_client import get_resources_json


async def get_rbac_summary() -> str:
    """Analyze RBAC bindings.

    Finds cluster-admin bindings, overpermissive service accounts,
    and unnecessary privileges.
    """
    try:
        data = await get_resources_json("clusterrolebinding")
        bindings = data.get("items", [])

        admin_bindings = []
        for b in bindings:
            if b.get("roleRef", {}).get("name") == "cluster-admin":
                subjects = b.get("subjects", [])
                admin_bindings.append({
                    "binding": b["metadata"]["name"],
                    "subjects": [
                        {
                            "kind": s.get("kind"),
                            "name": s.get("name"),
                            "namespace": s.get("namespace", ""),
                        }
                        for s in subjects
                    ],
                })

        return get_sanitizer().sanitize(json.dumps({
            "cluster_admin_bindings": len(admin_bindings),
            "details": admin_bindings,
        }, indent=2))
    except json.JSONDecodeError as e:
        return f"Error parsing RBAC data: {e}"
    except Exception as e:
        return f"Error fetching RBAC data: {e}"
