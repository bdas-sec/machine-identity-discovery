"""
NHI Security Operator — Kubernetes-native purple team automation.

Manages NHIScenario and NHIScenarioRun custom resources to orchestrate
attack simulations, create K8s Jobs for each phase, and poll Wazuh
for detection validation.

Environment variables:
    WAZUH_API_URL       Wazuh API base URL (default: https://wazuh-manager:55000)
    WAZUH_API_USER      Wazuh API username (default: wazuh-wui)
    WAZUH_API_PASSWORD  Wazuh API password (default: MyS3cr37P450r.*-)
    DETECTION_TIMEOUT   Seconds to wait for alerts after phases complete (default: 60)
    JOB_IMAGE           Container image for attack Jobs (default: alpine:3.19)
    JOB_NAMESPACE       Default namespace for Jobs if not specified (default: nhi-system)
"""

from __future__ import annotations

import asyncio
import logging
import os
import ssl
from datetime import datetime, timezone
from typing import Any

import aiohttp
import kopf
from kubernetes_asyncio import client, config
from kubernetes_asyncio.client import ApiException

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

WAZUH_API_URL = os.environ.get("WAZUH_API_URL", "https://wazuh-manager:55000")
WAZUH_API_USER = os.environ.get("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASSWORD = os.environ.get("WAZUH_API_PASSWORD", "MyS3cr37P450r.*-")
DETECTION_TIMEOUT = int(os.environ.get("DETECTION_TIMEOUT", "60"))
JOB_IMAGE = os.environ.get("JOB_IMAGE", "alpine:3.19")
JOB_NAMESPACE = os.environ.get("JOB_NAMESPACE", "nhi-system")

CRD_GROUP = "nhi.security"
CRD_VERSION = "v1alpha1"

logger = logging.getLogger("nhi-operator")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _utcnow() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build_job_manifest(
    run_name: str,
    phase_index: int,
    phase: dict,
    namespace: str,
) -> dict[str, Any]:
    """Build a Kubernetes Job manifest for a single attack phase.

    Each action in the phase becomes a sequential shell command inside a
    single init container, keeping the Job simple and auditable.
    """
    commands: list[str] = []
    for action in phase.get("actions", []):
        cmd = action.get("command", "echo 'no command'")
        commands.append(cmd)

    # Join all commands with '; ' so they run sequentially in one shell
    joined = " ; ".join(commands)

    job_name = f"nhi-{run_name}-phase-{phase_index}"
    # K8s name limit is 63 chars; truncate if needed
    job_name = job_name[:63].rstrip("-")

    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": job_name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/managed-by": "nhi-operator",
                "nhi.security/scenario-run": run_name,
                "nhi.security/phase-index": str(phase_index),
            },
        },
        "spec": {
            "backoffLimit": 0,
            "ttlSecondsAfterFinished": 600,
            "activeDeadlineSeconds": 120,
            "template": {
                "metadata": {
                    "labels": {
                        "app.kubernetes.io/managed-by": "nhi-operator",
                        "nhi.security/scenario-run": run_name,
                    },
                },
                "spec": {
                    "restartPolicy": "Never",
                    "containers": [
                        {
                            "name": "attack",
                            "image": JOB_IMAGE,
                            "command": ["/bin/sh", "-c", joined],
                            "resources": {
                                "limits": {"cpu": "200m", "memory": "128Mi"},
                                "requests": {"cpu": "50m", "memory": "32Mi"},
                            },
                        }
                    ],
                },
            },
        },
    }


async def _get_k8s_clients() -> tuple[client.BatchV1Api, client.CustomObjectsApi]:
    """Load kubeconfig (in-cluster or local) and return API clients."""
    try:
        config.load_incluster_config()
    except config.ConfigException:
        await config.load_kube_config()
    return client.BatchV1Api(), client.CustomObjectsApi()


async def _get_scenario(
    custom_api: client.CustomObjectsApi,
    name: str,
    namespace: str,
) -> dict[str, Any] | None:
    """Fetch an NHIScenario custom resource by name."""
    try:
        return await custom_api.get_namespaced_custom_object(
            group=CRD_GROUP,
            version=CRD_VERSION,
            namespace=namespace,
            plural="nhiscenarios",
            name=name,
        )
    except ApiException as exc:
        if exc.status == 404:
            return None
        raise


async def _create_job(
    batch_api: client.BatchV1Api,
    manifest: dict[str, Any],
) -> str:
    """Create a K8s Job and return its name."""
    ns = manifest["metadata"]["namespace"]
    resp = await batch_api.create_namespaced_job(namespace=ns, body=manifest)
    return resp.metadata.name


async def _wait_for_job(
    batch_api: client.BatchV1Api,
    job_name: str,
    namespace: str,
    timeout: int = 120,
) -> bool:
    """Wait for a Job to complete. Returns True on success, False on failure."""
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        try:
            job = await batch_api.read_namespaced_job_status(
                name=job_name, namespace=namespace
            )
        except ApiException:
            await asyncio.sleep(2)
            continue

        status = job.status
        if status.succeeded and status.succeeded > 0:
            return True
        if status.failed and status.failed > 0:
            return False

        await asyncio.sleep(2)
    return False


async def _delete_jobs_for_run(
    batch_api: client.BatchV1Api,
    run_name: str,
    namespace: str,
) -> int:
    """Delete all Jobs associated with a scenario run. Returns count deleted."""
    label_selector = f"nhi.security/scenario-run={run_name}"
    try:
        jobs = await batch_api.list_namespaced_job(
            namespace=namespace, label_selector=label_selector
        )
    except ApiException:
        return 0

    count = 0
    for job in jobs.items:
        try:
            await batch_api.delete_namespaced_job(
                name=job.metadata.name,
                namespace=namespace,
                body=client.V1DeleteOptions(propagation_policy="Background"),
            )
            count += 1
        except ApiException:
            pass
    return count


# ---------------------------------------------------------------------------
# Wazuh API Client
# ---------------------------------------------------------------------------


class WazuhClient:
    """Async client for the Wazuh REST API."""

    def __init__(
        self,
        base_url: str = WAZUH_API_URL,
        user: str = WAZUH_API_USER,
        password: str = WAZUH_API_PASSWORD,
    ):
        self.base_url = base_url.rstrip("/")
        self.user = user
        self.password = password
        self._token: str | None = None

    def _ssl_context(self) -> ssl.SSLContext:
        """Create a permissive SSL context for self-signed Wazuh certs."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    async def authenticate(self) -> None:
        """Obtain a JWT token from Wazuh API."""
        url = f"{self.base_url}/security/user/authenticate"
        auth = aiohttp.BasicAuth(self.user, self.password)
        async with aiohttp.ClientSession() as session:
            async with session.post(
                url, auth=auth, ssl=self._ssl_context()
            ) as resp:
                if resp.status != 200:
                    body = await resp.text()
                    raise RuntimeError(
                        f"Wazuh auth failed ({resp.status}): {body}"
                    )
                data = await resp.json()
                self._token = data.get("data", {}).get("token")
                if not self._token:
                    raise RuntimeError("No token in Wazuh auth response")
        logger.info("Wazuh API authentication successful")

    async def get_alerts(
        self,
        rule_ids: list[str],
        since: str | None = None,
        limit: int = 500,
    ) -> list[dict[str, Any]]:
        """Query Wazuh for alerts matching the given rule IDs.

        Args:
            rule_ids: List of Wazuh rule IDs to search for.
            since: ISO-8601 timestamp; only return alerts after this time.
            limit: Maximum number of alerts to return.

        Returns:
            List of alert dicts with keys: rule_id, level, description, timestamp.
        """
        if not self._token:
            await self.authenticate()

        # Build the query filter for rule IDs
        rule_filter = ",".join(rule_ids)
        params: dict[str, Any] = {
            "limit": limit,
            "sort": "-timestamp",
            "q": f"rule.id={rule_filter}",
        }
        if since:
            params["older_than"] = "0s"
            params["date_from"] = since

        url = f"{self.base_url}/alerts"
        headers = {"Authorization": f"Bearer {self._token}"}

        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                headers=headers,
                params=params,
                ssl=self._ssl_context(),
            ) as resp:
                if resp.status == 401:
                    # Token expired, re-authenticate and retry
                    await self.authenticate()
                    headers["Authorization"] = f"Bearer {self._token}"
                    async with session.get(
                        url,
                        headers=headers,
                        params=params,
                        ssl=self._ssl_context(),
                    ) as retry_resp:
                        data = await retry_resp.json()
                elif resp.status != 200:
                    body = await resp.text()
                    logger.warning(
                        "Wazuh alerts query failed (%d): %s", resp.status, body
                    )
                    return []
                else:
                    data = await resp.json()

        alerts = []
        for item in data.get("data", {}).get("affected_items", []):
            rule = item.get("rule", {})
            alerts.append(
                {
                    "rule_id": str(rule.get("id", "")),
                    "level": rule.get("level", 0),
                    "description": rule.get("description", ""),
                    "timestamp": item.get("timestamp", ""),
                }
            )
        return alerts


# Module-level Wazuh client, reused across handlers
_wazuh = WazuhClient()

# ---------------------------------------------------------------------------
# Kopf Handlers — NHIScenario
# ---------------------------------------------------------------------------


@kopf.on.create(CRD_GROUP, CRD_VERSION, "nhiscenarios")
async def scenario_created(
    spec: dict, name: str, namespace: str, patch: dict, **kwargs: Any
) -> dict[str, Any]:
    """Handle creation of an NHIScenario resource.

    Validates the scenario definition, sets the computed phaseCount field,
    and logs the registration.
    """
    phases = spec.get("phases", [])
    phase_count = len(phases)
    category = spec.get("category", "unknown")
    difficulty = spec.get("difficulty", "Medium")

    # Set phaseCount for the printer column
    patch["spec"] = {"phaseCount": phase_count}

    # Validate that each phase has at least one action
    for idx, phase in enumerate(phases):
        actions = phase.get("actions", [])
        if not actions:
            raise kopf.PermanentError(
                f"Phase {idx} ({phase.get('name', 'unnamed')}) has no actions"
            )

    expected_alerts = spec.get("expectedAlerts", [])
    logger.info(
        "Registered NHIScenario %s/%s: category=%s, difficulty=%s, "
        "phases=%d, expected_alerts=%d",
        namespace,
        name,
        category,
        difficulty,
        phase_count,
        len(expected_alerts),
    )

    return {
        "registered": True,
        "phaseCount": phase_count,
        "expectedAlertCount": len(expected_alerts),
    }


@kopf.on.update(CRD_GROUP, CRD_VERSION, "nhiscenarios")
async def scenario_updated(
    spec: dict, name: str, namespace: str, patch: dict, **kwargs: Any
) -> dict[str, Any]:
    """Re-validate and update phaseCount on scenario modification."""
    phases = spec.get("phases", [])
    patch["spec"] = {"phaseCount": len(phases)}
    logger.info(
        "Updated NHIScenario %s/%s: phases=%d", namespace, name, len(phases)
    )
    return {"phaseCount": len(phases)}


# ---------------------------------------------------------------------------
# Kopf Handlers — NHIScenarioRun
# ---------------------------------------------------------------------------


@kopf.on.create(CRD_GROUP, CRD_VERSION, "nhiscenarioruns")
async def run_created(
    spec: dict,
    name: str,
    namespace: str,
    patch: dict,
    **kwargs: Any,
) -> dict[str, Any]:
    """Main execution handler for NHIScenarioRun.

    Workflow:
        1. Look up the referenced NHIScenario
        2. Set status to Running
        3. Create a K8s Job for each attack phase
        4. Wait for each Job to complete
        5. Transition to Detecting phase
        6. Initial Wazuh poll (timer handles subsequent polls)
        7. Update status with results
    """
    scenario_ref = spec["scenarioRef"]
    target_ns = spec.get("targetNamespace") or namespace
    dry_run = spec.get("dryRun", False)
    timeout = spec.get("timeout", 300)

    # Initialize status
    patch["status"] = {
        "phase": "Pending",
        "startTime": _utcnow(),
        "currentPhase": 0,
        "totalPhases": 0,
        "detectedAlerts": [],
        "detectionRate": "0/0 (0%)",
        "detectionLatency": "N/A",
        "message": f"Looking up scenario {scenario_ref}",
    }

    # Fetch the referenced scenario
    _, custom_api = await _get_k8s_clients()
    scenario = await _get_scenario(custom_api, scenario_ref, namespace)

    if scenario is None:
        patch["status"]["phase"] = "Failed"
        patch["status"]["completionTime"] = _utcnow()
        patch["status"]["message"] = (
            f"NHIScenario '{scenario_ref}' not found in namespace '{namespace}'"
        )
        raise kopf.PermanentError(f"Scenario '{scenario_ref}' not found")

    scenario_spec = scenario.get("spec", {})
    phases = scenario_spec.get("phases", [])
    expected_alerts = scenario_spec.get("expectedAlerts", [])

    patch["status"]["totalPhases"] = len(phases)
    patch["status"]["message"] = f"Executing {len(phases)} phases"

    if dry_run:
        patch["status"]["phase"] = "Completed"
        patch["status"]["completionTime"] = _utcnow()
        patch["status"]["message"] = (
            f"Dry run complete: {len(phases)} phases validated, "
            f"{len(expected_alerts)} alerts expected"
        )
        logger.info(
            "Dry run for %s/%s: %d phases, %d expected alerts",
            namespace,
            name,
            len(phases),
            len(expected_alerts),
        )
        return {"dryRun": True, "phases": len(phases)}

    # Transition to Running
    patch["status"]["phase"] = "Running"

    # Execute each phase as a K8s Job
    batch_api, _ = await _get_k8s_clients()
    attack_start_time = _utcnow()
    phase_results: list[dict[str, Any]] = []

    for idx, phase in enumerate(phases):
        phase_name = phase.get("name", f"phase-{idx}")
        is_critical = phase.get("critical", False)

        patch["status"]["currentPhase"] = idx
        patch["status"]["message"] = f"Executing phase {idx}: {phase_name}"

        logger.info(
            "Run %s/%s: starting phase %d/%d — %s (critical=%s)",
            namespace,
            name,
            idx + 1,
            len(phases),
            phase_name,
            is_critical,
        )

        job_manifest = _build_job_manifest(name, idx, phase, target_ns)
        try:
            job_name = await _create_job(batch_api, job_manifest)
        except ApiException as exc:
            msg = f"Failed to create Job for phase {idx}: {exc.reason}"
            logger.error(msg)
            if is_critical:
                patch["status"]["phase"] = "Failed"
                patch["status"]["completionTime"] = _utcnow()
                patch["status"]["message"] = msg
                raise kopf.PermanentError(msg)
            phase_results.append(
                {"phase": idx, "name": phase_name, "status": "error", "error": msg}
            )
            continue

        # Wait for the Job to finish
        phase_timeout = min(timeout // max(len(phases), 1), 120)
        success = await _wait_for_job(batch_api, job_name, target_ns, phase_timeout)

        if success:
            phase_results.append(
                {"phase": idx, "name": phase_name, "status": "succeeded"}
            )
            logger.info("Phase %d/%d succeeded: %s", idx + 1, len(phases), phase_name)
        else:
            phase_results.append(
                {"phase": idx, "name": phase_name, "status": "failed"}
            )
            logger.warning(
                "Phase %d/%d failed: %s (critical=%s)",
                idx + 1,
                len(phases),
                phase_name,
                is_critical,
            )
            if is_critical:
                patch["status"]["phase"] = "Failed"
                patch["status"]["completionTime"] = _utcnow()
                patch["status"]["message"] = (
                    f"Critical phase {idx} ({phase_name}) failed"
                )
                raise kopf.PermanentError(
                    f"Critical phase '{phase_name}' failed"
                )

    # All phases done — enter Detecting phase
    patch["status"]["phase"] = "Detecting"
    patch["status"]["currentPhase"] = len(phases)
    patch["status"]["message"] = (
        f"All {len(phases)} phases complete. "
        f"Waiting for {len(expected_alerts)} alerts (timeout: {DETECTION_TIMEOUT}s)"
    )

    logger.info(
        "Run %s/%s: all phases complete, entering detection window "
        "(expecting %d alerts, timeout %ds)",
        namespace,
        name,
        len(expected_alerts),
        DETECTION_TIMEOUT,
    )

    # Store metadata for the detection timer
    return {
        "phaseResults": phase_results,
        "attackStartTime": attack_start_time,
        "attackEndTime": _utcnow(),
        "expectedRuleIds": [a["ruleId"] for a in expected_alerts],
        "expectedAlerts": expected_alerts,
    }


@kopf.timer(
    CRD_GROUP,
    CRD_VERSION,
    "nhiscenarioruns",
    interval=10.0,
    idle=5,
)
async def check_detection(
    spec: dict,
    name: str,
    namespace: str,
    status: dict,
    patch: dict,
    memo: kopf.Memo,
    **kwargs: Any,
) -> None:
    """Periodic timer that polls Wazuh API during the Detecting phase.

    Once all expected alerts are found or the detection timeout expires,
    the run transitions to Completed with detection metrics.
    """
    current_phase = status.get("phase", "")

    # Only act during Detecting phase
    if current_phase != "Detecting":
        return

    handler_result = kwargs.get("handler_result") or {}
    # Try to get data from the create handler's return value stored in annotations
    # kopf stores handler results — access via the run's status
    run_info = status.get("run_created") or status.get("scenario_run_created") or {}

    # Fall back to looking at the kopf handler results stored in the object
    expected_rule_ids: list[str] = []
    expected_alerts: list[dict] = []
    attack_start: str = ""

    # kopf stores create handler results under status.create_handler_name
    # We need to traverse possible locations
    for key in ("run_created", "scenario_run_created"):
        info = status.get(key, {})
        if info:
            expected_rule_ids = info.get("expectedRuleIds", [])
            expected_alerts = info.get("expectedAlerts", [])
            attack_start = info.get("attackStartTime", "")
            break

    if not expected_rule_ids:
        # No expected alerts — mark complete immediately
        patch["status"] = {
            "phase": "Completed",
            "completionTime": _utcnow(),
            "detectionRate": "0/0 (N/A)",
            "detectionLatency": "N/A",
            "message": "No expected alerts defined — scenario complete",
        }
        return

    # Check detection timeout
    start_time_str = status.get("startTime", "")
    if start_time_str:
        try:
            start_dt = datetime.fromisoformat(
                start_time_str.replace("Z", "+00:00")
            )
            elapsed = (datetime.now(timezone.utc) - start_dt).total_seconds()
            timeout = spec.get("timeout", 300)
            if elapsed > timeout:
                _finalize_detection(
                    patch,
                    expected_alerts,
                    status.get("detectedAlerts", []),
                    attack_start,
                    timed_out=True,
                )
                return
        except (ValueError, TypeError):
            pass

    # Poll Wazuh for matching alerts
    try:
        wazuh_alerts = await _wazuh.get_alerts(
            rule_ids=expected_rule_ids,
            since=attack_start or None,
        )
    except Exception as exc:
        logger.warning("Wazuh poll failed for run %s/%s: %s", namespace, name, exc)
        # Track the failure but do not transition — retry on next timer tick
        memo.setdefault("wazuh_failures", 0)
        memo["wazuh_failures"] = memo.get("wazuh_failures", 0) + 1
        if memo["wazuh_failures"] >= 6:  # ~60s of failures
            patch["status"] = {
                "phase": "Failed",
                "completionTime": _utcnow(),
                "message": f"Wazuh API unreachable after multiple retries: {exc}",
            }
        return

    # De-duplicate alerts by rule ID
    seen_rule_ids: set[str] = set()
    unique_alerts: list[dict[str, Any]] = []
    for alert in wazuh_alerts:
        rid = alert["rule_id"]
        if rid not in seen_rule_ids:
            seen_rule_ids.add(rid)
            unique_alerts.append(
                {
                    "ruleId": rid,
                    "level": alert.get("level", 0),
                    "description": alert.get("description", ""),
                    "timestamp": alert.get("timestamp", _utcnow()),
                }
            )

    patch.setdefault("status", {})
    patch["status"]["detectedAlerts"] = unique_alerts

    # Check if we have all expected alerts
    detected_ids = {a["ruleId"] for a in unique_alerts}
    expected_ids = set(expected_rule_ids)

    if expected_ids.issubset(detected_ids):
        # All expected alerts detected
        _finalize_detection(
            patch, expected_alerts, unique_alerts, attack_start, timed_out=False
        )
        logger.info(
            "Run %s/%s: all %d expected alerts detected",
            namespace,
            name,
            len(expected_ids),
        )
    else:
        missing = expected_ids - detected_ids
        detected = len(expected_ids) - len(missing)
        total = len(expected_ids)
        pct = int((detected / total) * 100) if total > 0 else 0
        patch["status"]["detectionRate"] = f"{detected}/{total} ({pct}%)"
        patch["status"]["message"] = (
            f"Waiting for alerts: {detected}/{total} detected, "
            f"missing rule IDs: {sorted(missing)}"
        )


def _finalize_detection(
    patch: dict,
    expected_alerts: list[dict],
    detected_alerts: list[dict],
    attack_start: str,
    timed_out: bool,
) -> None:
    """Calculate final detection metrics and set Completed status."""
    expected_ids = {a.get("ruleId", a.get("rule_id", "")) for a in expected_alerts}
    detected_ids = {a.get("ruleId", a.get("rule_id", "")) for a in detected_alerts}
    matched = expected_ids & detected_ids
    total = len(expected_ids)
    detected_count = len(matched)
    pct = int((detected_count / total) * 100) if total > 0 else 0

    # Calculate average detection latency
    latency_str = "N/A"
    if attack_start and detected_alerts:
        try:
            start_dt = datetime.fromisoformat(
                attack_start.replace("Z", "+00:00")
            )
            latencies: list[float] = []
            for alert in detected_alerts:
                ts = alert.get("timestamp", "")
                if ts:
                    alert_dt = datetime.fromisoformat(
                        ts.replace("Z", "+00:00")
                    )
                    delta = (alert_dt - start_dt).total_seconds()
                    if delta >= 0:
                        latencies.append(delta)
            if latencies:
                avg = sum(latencies) / len(latencies)
                latency_str = f"{avg:.1f}s"
        except (ValueError, TypeError):
            pass

    timeout_note = " (detection timeout reached)" if timed_out else ""
    patch.setdefault("status", {})
    patch["status"].update(
        {
            "phase": "Completed",
            "completionTime": _utcnow(),
            "detectionRate": f"{detected_count}/{total} ({pct}%)",
            "detectionLatency": latency_str,
            "message": (
                f"Detection complete: {detected_count}/{total} alerts matched "
                f"({pct}%){timeout_note}"
            ),
        }
    )


@kopf.on.delete(CRD_GROUP, CRD_VERSION, "nhiscenarioruns")
async def run_deleted(
    spec: dict, name: str, namespace: str, **kwargs: Any
) -> None:
    """Clean up Jobs created for this scenario run."""
    target_ns = spec.get("targetNamespace") or namespace
    batch_api, _ = await _get_k8s_clients()
    count = await _delete_jobs_for_run(batch_api, name, target_ns)
    logger.info(
        "Deleted %d Jobs for run %s/%s", count, namespace, name
    )


# ---------------------------------------------------------------------------
# Startup / Shutdown
# ---------------------------------------------------------------------------


@kopf.on.startup()
async def operator_startup(settings: kopf.OperatorSettings, **kwargs: Any) -> None:
    """Configure operator settings on startup."""
    # Use a shorter persistence interval for faster status updates
    settings.persistence.finalizer = "nhi.security/finalizer"
    settings.persistence.progress_storage = kopf.AnnotationsProgressStorage(
        prefix="nhi.security"
    )
    # Batch posting interval for events
    settings.posting.level = logging.WARNING

    logger.info(
        "NHI Security Operator started — Wazuh API: %s, detection timeout: %ds",
        WAZUH_API_URL,
        DETECTION_TIMEOUT,
    )


@kopf.on.cleanup()
async def operator_cleanup(**kwargs: Any) -> None:
    """Graceful shutdown."""
    logger.info("NHI Security Operator shutting down")
