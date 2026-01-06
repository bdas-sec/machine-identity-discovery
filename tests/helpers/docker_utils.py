"""
Docker/Podman utilities for testing.
"""

import os
import shutil
import subprocess
from typing import Dict, List, Optional, Tuple, Any


def _get_container_runtime() -> str:
    """Detect available container runtime (podman or docker)."""
    # Check CONTAINER_RUNTIME env var first
    runtime = os.environ.get("CONTAINER_RUNTIME", "").lower()
    if runtime in ("podman", "docker"):
        return runtime
    # Auto-detect
    if shutil.which("podman"):
        return "podman"
    if shutil.which("docker"):
        return "docker"
    return "docker"  # Default fallback


CONTAINER_RUNTIME = _get_container_runtime()


class DockerTestUtils:
    """Utilities for Docker/Podman-based testing."""

    def __init__(self, docker_client=None):
        self.docker = docker_client
        self.runtime = CONTAINER_RUNTIME

    @staticmethod
    def exec_in_container(
        container_name: str,
        command: str,
        timeout: int = 30
    ) -> Tuple[int, str, str]:
        """
        Execute a command in a container.

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        try:
            result = subprocess.run(
                [CONTAINER_RUNTIME, "exec", container_name, "sh", "-c", command],
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)

    @staticmethod
    def container_exists(container_name: str) -> bool:
        """Check if a container exists."""
        result = subprocess.run(
            [CONTAINER_RUNTIME, "ps", "-a", "--filter", f"name=^{container_name}$", "-q"],
            capture_output=True,
            text=True
        )
        return bool(result.stdout.strip())

    @staticmethod
    def container_running(container_name: str) -> bool:
        """Check if a container is running."""
        result = subprocess.run(
            [CONTAINER_RUNTIME, "ps", "--filter", f"name=^{container_name}$", "-q"],
            capture_output=True,
            text=True
        )
        return bool(result.stdout.strip())

    @staticmethod
    def get_container_status(container_name: str) -> Optional[str]:
        """Get container status."""
        result = subprocess.run(
            [CONTAINER_RUNTIME, "inspect", "-f", "{{.State.Status}}", container_name],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return None

    @staticmethod
    def get_container_health(container_name: str) -> Optional[str]:
        """Get container health status."""
        result = subprocess.run(
            [CONTAINER_RUNTIME, "inspect", "-f", "{{.State.Health.Status}}", container_name],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            status = result.stdout.strip()
            return status if status != "<no value>" else None
        return None

    @staticmethod
    def get_running_containers() -> List[str]:
        """Get list of running container names."""
        result = subprocess.run(
            [CONTAINER_RUNTIME, "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return [name for name in result.stdout.strip().split("\n") if name]
        return []

    @staticmethod
    def get_container_networks(container_name: str) -> List[str]:
        """Get networks a container is connected to."""
        result = subprocess.run(
            [CONTAINER_RUNTIME, "inspect", "-f",
             "{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}",
             container_name],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return result.stdout.strip().split()
        return []

    @staticmethod
    def network_exists(network_name: str) -> bool:
        """Check if a container network exists."""
        result = subprocess.run(
            [CONTAINER_RUNTIME, "network", "ls", "--filter", f"name={network_name}", "-q"],
            capture_output=True,
            text=True
        )
        return bool(result.stdout.strip())

    @staticmethod
    def get_container_ip(container_name: str, network: str = None) -> Optional[str]:
        """Get container IP address."""
        if network:
            template = f"{{{{.NetworkSettings.Networks.{network}.IPAddress}}}}"
        else:
            template = "{{.NetworkSettings.IPAddress}}"

        result = subprocess.run(
            [CONTAINER_RUNTIME, "inspect", "-f", template, container_name],
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            ip = result.stdout.strip()
            return ip if ip else None
        return None

    @staticmethod
    def can_reach(
        from_container: str,
        target_host: str,
        target_port: int,
        timeout: int = 5
    ) -> bool:
        """Test if one container can reach another on a specific port.

        Tries multiple methods: nc, curl, bash /dev/tcp (in that order).
        """
        # Try netcat first
        exit_code, _, _ = DockerTestUtils.exec_in_container(
            from_container,
            f"nc -z -w{timeout} {target_host} {target_port}",
            timeout=timeout + 2
        )
        if exit_code == 0:
            return True

        # Try curl (for HTTP/HTTPS ports)
        exit_code, _, _ = DockerTestUtils.exec_in_container(
            from_container,
            f"curl -sk --connect-timeout {timeout} --max-time {timeout} https://{target_host}:{target_port}/ -o /dev/null -w '%{{http_code}}' 2>/dev/null || "
            f"curl -s --connect-timeout {timeout} --max-time {timeout} http://{target_host}:{target_port}/ -o /dev/null -w '%{{http_code}}' 2>/dev/null",
            timeout=timeout + 5
        )
        if exit_code == 0:
            return True

        # Try bash /dev/tcp as last resort
        exit_code, _, _ = DockerTestUtils.exec_in_container(
            from_container,
            f"timeout {timeout} bash -c 'echo > /dev/tcp/{target_host}/{target_port}' 2>/dev/null",
            timeout=timeout + 2
        )
        return exit_code == 0

    @staticmethod
    def get_container_logs(
        container_name: str,
        lines: int = 100,
        since: str = None
    ) -> str:
        """Get container logs."""
        cmd = [CONTAINER_RUNTIME, "logs", "--tail", str(lines)]
        if since:
            cmd.extend(["--since", since])
        cmd.append(container_name)

        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout + result.stderr

    @staticmethod
    def get_container_env(container_name: str) -> Dict[str, str]:
        """Get container environment variables."""
        result = subprocess.run(
            [CONTAINER_RUNTIME, "inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}",
             container_name],
            capture_output=True,
            text=True
        )
        env = {}
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if "=" in line:
                    key, value = line.split("=", 1)
                    env[key] = value
        return env
