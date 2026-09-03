"""CIS Benchmark checks via kube-bench Kubernetes Job.

Uses kagent-tool-server to create the Job and read logs. Falls back to
subprocess kubectl if the tool server doesn't have write access.
"""

import asyncio
import json
import logging
import os

from k8s_sec_agent.sanitizer import get_sanitizer
from k8s_sec_agent.tools.k8s_client import (
    apply_manifest,
    delete_resource,
    get_pod_logs,
    get_resources_json,
)

logger = logging.getLogger(__name__)

KUBE_BENCH_IMAGE = os.environ.get("KUBE_BENCH_IMAGE", "aquasec/kube-bench:latest")

_JOB_MANIFEST_TEMPLATE = """\
apiVersion: batch/v1
kind: Job
metadata:
  name: kube-bench-audit
  namespace: default
spec:
  ttlSecondsAfterFinished: 60
  template:
    spec:
      hostPID: true
      restartPolicy: Never
      containers:
        - name: kube-bench
          image: {image}
          command: ["kube-bench", "run", "--targets", "node", "--json"]
          volumeMounts:
            - name: etc-kubernetes
              mountPath: /etc/kubernetes
              readOnly: true
            - name: proc
              mountPath: /host/proc
              readOnly: true
      volumes:
        - name: etc-kubernetes
          hostPath:
            path: /etc/kubernetes
        - name: proc
          hostPath:
            path: /proc
"""

MAX_OUTPUT_CHARS = 50000


async def _wait_for_job(timeout: int = 120) -> bool:
    """Poll until the kube-bench-audit job completes or times out."""
    for _ in range(timeout // 5):
        await asyncio.sleep(5)
        try:
            data = await get_resources_json(
                "job",
                resource_name="kube-bench-audit",
                namespace="default",
            )
            # Single resource response
            conditions = data.get("status", {}).get("conditions", [])
            for c in conditions:
                if c.get("type") == "Complete" and c.get("status") == "True":
                    return True
                if c.get("type") == "Failed" and c.get("status") == "True":
                    return False
        except Exception:
            continue
    return False


async def run_kube_bench() -> str:
    """Run kube-bench CIS Benchmark checks on worker nodes.

    Creates a Job via kagent-tool-server, waits for completion,
    returns sanitized JSON results with pass/fail/warn per check.
    """
    try:
        # Clean up any previous run
        try:
            await delete_resource("job", "kube-bench-audit", namespace="default")
        except Exception:
            pass  # Job doesn't exist, that's fine

        # Create the kube-bench job
        manifest = _JOB_MANIFEST_TEMPLATE.format(image=KUBE_BENCH_IMAGE)
        await apply_manifest(manifest)

        # Wait for job completion
        completed = await _wait_for_job(timeout=120)
        if not completed:
            return "Error: kube-bench job timed out or failed"

        # Get the pod name for the job
        pods = await get_resources_json("pod", namespace="default")
        bench_pod = None
        for pod in pods.get("items", []):
            name = pod["metadata"].get("name", "")
            if name.startswith("kube-bench-audit-"):
                bench_pod = name
                break

        if not bench_pod:
            return "Error: could not find kube-bench pod"

        # Read logs
        output = await get_pod_logs(bench_pod, namespace="default", tail_lines=1000)

        if len(output) > MAX_OUTPUT_CHARS:
            output = output[:MAX_OUTPUT_CHARS] + "\n... (truncated)"

        return get_sanitizer().sanitize(output)

    except Exception as e:
        return f"Error running kube-bench: {e}"
