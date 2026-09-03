"""MCP server exposing Kubernetes CIS audit tools with sanitization."""

from fastmcp import FastMCP, Context

from k8s_sec_agent.sanitizer import set_session
from k8s_sec_agent.tools.kubectl import run_kubectl as _run_kubectl
from k8s_sec_agent.tools.kube_bench import run_kube_bench as _run_kube_bench
from k8s_sec_agent.tools.pod_security import get_pod_security_summary as _get_pod_security_summary
from k8s_sec_agent.tools.network_policy import get_network_policy_coverage as _get_network_policy_coverage
from k8s_sec_agent.tools.rbac import get_rbac_summary as _get_rbac_summary

mcp = FastMCP("k8s-sec-tools")


def _activate_session(ctx: Context) -> None:
    """Activate the session-scoped sanitizer for this tool call."""
    try:
        set_session(ctx.session_id)
    except (RuntimeError, AttributeError):
        pass  # No session — falls back to current sanitizer


@mcp.tool()
async def run_kubectl(command: str, ctx: Context) -> str:
    """Run a kubectl command against the cluster.

    Use for any Kubernetes API query not covered by the specialized tools.

    Args:
        command: kubectl command without 'kubectl' prefix (e.g. 'get pods -A -o json').
    """
    _activate_session(ctx)
    return await _run_kubectl(command)


@mcp.tool()
async def run_kube_bench(ctx: Context) -> str:
    """Run kube-bench CIS Benchmark checks on worker nodes.

    Creates a Job, waits for completion, returns JSON results with
    pass/fail/warn per check.
    """
    _activate_session(ctx)
    return await _run_kube_bench()


@mcp.tool()
async def get_pod_security_summary(ctx: Context) -> str:
    """Scan all pods for security issues.

    Checks for privileged containers, root execution, missing resource
    limits, and writable root filesystems.
    """
    _activate_session(ctx)
    return await _get_pod_security_summary()


@mcp.tool()
async def get_network_policy_coverage(ctx: Context) -> str:
    """Check network policy coverage per namespace.

    Identifies namespaces with no policies (default allow-all traffic).
    """
    _activate_session(ctx)
    return await _get_network_policy_coverage()


@mcp.tool()
async def get_rbac_summary(ctx: Context) -> str:
    """Analyze RBAC bindings.

    Finds cluster-admin bindings, overpermissive service accounts,
    and unnecessary privileges.
    """
    _activate_session(ctx)
    return await _get_rbac_summary()
