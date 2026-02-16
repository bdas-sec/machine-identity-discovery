"""
Smoke tests for Podman compatibility validation.

Validates that the NHI Security Testbed works correctly with
Podman as an alternative to Docker. Tests rootless mode,
volume mounts, network creation, and compose compatibility.
"""

import os
import shutil
import subprocess
import pytest
import yaml
from pathlib import Path


PROJECT_ROOT = Path(__file__).parent.parent.parent
DOCKER_COMPOSE_FILE = PROJECT_ROOT / "docker-compose.yml"


def _get_runtime():
    """Get the active container runtime."""
    runtime = os.environ.get("CONTAINER_RUNTIME", "").lower()
    if runtime in ("podman", "docker"):
        return runtime
    if shutil.which("podman"):
        return "podman"
    if shutil.which("docker"):
        return "docker"
    return None


def _skip_if_no_podman():
    """Skip if podman is not available."""
    if not shutil.which("podman"):
        pytest.skip("podman binary not available")


def _skip_if_no_podman_compose():
    """Skip if podman-compose is not available."""
    if not shutil.which("podman-compose"):
        pytest.skip("podman-compose binary not available")


@pytest.mark.smoke
class TestPodmanAvailability:
    """Verify Podman toolchain is available."""

    def test_podman_binary_exists(self):
        """podman binary is on PATH."""
        _skip_if_no_podman()
        result = subprocess.run(
            ["podman", "--version"],
            capture_output=True, text=True, timeout=10
        )
        assert result.returncode == 0, f"podman --version failed: {result.stderr}"
        assert "podman" in result.stdout.lower(), \
            f"Unexpected version output: {result.stdout}"

    def test_podman_compose_binary_exists(self):
        """podman-compose binary is on PATH."""
        _skip_if_no_podman_compose()
        result = subprocess.run(
            ["podman-compose", "version"],
            capture_output=True, text=True, timeout=10
        )
        assert result.returncode == 0, \
            f"podman-compose version failed: {result.stderr}"

    def test_podman_info(self):
        """podman info returns system information."""
        _skip_if_no_podman()
        result = subprocess.run(
            ["podman", "info", "--format", "json"],
            capture_output=True, text=True, timeout=15
        )
        assert result.returncode == 0, f"podman info failed: {result.stderr}"


@pytest.mark.smoke
class TestPodmanComposeCompatibility:
    """Verify docker-compose.yml is compatible with Podman."""

    @pytest.fixture(autouse=True)
    def _check_podman(self):
        _skip_if_no_podman()

    def test_compose_file_parseable(self):
        """docker-compose.yml is valid YAML."""
        assert DOCKER_COMPOSE_FILE.exists(), "docker-compose.yml not found"
        with open(DOCKER_COMPOSE_FILE) as f:
            config = yaml.safe_load(f)
        assert "services" in config, "Missing services section"

    def test_no_docker_specific_features(self):
        """Compose file doesn't use Docker-only features unsupported by Podman."""
        with open(DOCKER_COMPOSE_FILE) as f:
            config = yaml.safe_load(f)

        for svc_name, svc in config.get("services", {}).items():
            # Podman doesn't support some Docker-specific options
            if "deploy" in svc:
                deploy = svc["deploy"]
                assert "placement" not in deploy or "constraints" not in deploy.get("placement", {}), \
                    f"Service {svc_name} uses Docker Swarm placement constraints"

    def test_rootless_port_mappings(self):
        """All port mappings use unprivileged ports (>1024) for rootless mode."""
        with open(DOCKER_COMPOSE_FILE) as f:
            config = yaml.safe_load(f)

        for svc_name, svc in config.get("services", {}).items():
            ports = svc.get("ports", [])
            for port_map in ports:
                port_str = str(port_map)
                # Extract host port from mapping like "8443:443" or "55000:55000"
                if ":" in port_str:
                    host_port = port_str.split(":")[0]
                    # Handle "0.0.0.0:8443" format
                    if "." in host_port:
                        host_port = host_port.split(".")[-1]
                        if ":" in host_port:
                            host_port = host_port.split(":")[-1]
                    try:
                        port_num = int(host_port)
                        assert port_num > 1024 or port_num == 0, \
                            f"Service {svc_name} maps to privileged port {port_num} " \
                            f"(incompatible with rootless Podman)"
                    except ValueError:
                        pass  # Dynamic port assignment

    def test_volume_mount_formats(self):
        """Volume mounts use formats compatible with Podman."""
        with open(DOCKER_COMPOSE_FILE) as f:
            config = yaml.safe_load(f)

        for svc_name, svc in config.get("services", {}).items():
            volumes = svc.get("volumes", [])
            for vol in volumes:
                vol_str = str(vol)
                # Named volumes and bind mounts should work
                # Check for unsupported volume drivers
                if isinstance(vol, dict) and "driver" in vol:
                    assert vol["driver"] in ["local", ""], \
                        f"Service {svc_name} uses unsupported volume driver: {vol['driver']}"


@pytest.mark.smoke
class TestPodmanNetworking:
    """Verify Podman can create required networks."""

    @pytest.fixture(autouse=True)
    def _check_podman(self):
        _skip_if_no_podman()

    def test_network_creation(self):
        """Podman can create a test network."""
        net_name = "nhi-test-net-validation"
        # Clean up if exists
        subprocess.run(
            ["podman", "network", "rm", net_name],
            capture_output=True, timeout=10
        )
        # Create network
        result = subprocess.run(
            ["podman", "network", "create", net_name],
            capture_output=True, text=True, timeout=10
        )
        assert result.returncode == 0, \
            f"Network creation failed: {result.stderr}"

        # Verify it exists
        result = subprocess.run(
            ["podman", "network", "ls", "--filter", f"name={net_name}", "-q"],
            capture_output=True, text=True, timeout=10
        )
        assert net_name in result.stdout or result.stdout.strip(), \
            "Created network not found in listing"

        # Clean up
        subprocess.run(
            ["podman", "network", "rm", net_name],
            capture_output=True, timeout=10
        )

    def test_subnet_network_creation(self):
        """Podman can create a network with a specific subnet."""
        net_name = "nhi-test-subnet-validation"
        subprocess.run(
            ["podman", "network", "rm", net_name],
            capture_output=True, timeout=10
        )
        result = subprocess.run(
            ["podman", "network", "create", "--subnet", "172.99.0.0/24", net_name],
            capture_output=True, text=True, timeout=10
        )
        assert result.returncode == 0, \
            f"Subnet network creation failed: {result.stderr}"

        # Clean up
        subprocess.run(
            ["podman", "network", "rm", net_name],
            capture_output=True, timeout=10
        )


@pytest.mark.smoke
class TestPodmanImageAccess:
    """Verify all required container images are accessible."""

    @pytest.fixture(autouse=True)
    def _check_podman(self):
        _skip_if_no_podman()

    def test_compose_images_defined(self):
        """All services in compose file have image or build defined."""
        with open(DOCKER_COMPOSE_FILE) as f:
            config = yaml.safe_load(f)

        for svc_name, svc in config.get("services", {}).items():
            has_image = "image" in svc
            has_build = "build" in svc
            assert has_image or has_build, \
                f"Service {svc_name} has neither 'image' nor 'build' defined"

    def test_local_builds_have_dockerfiles(self):
        """Services with build contexts have valid Dockerfiles."""
        with open(DOCKER_COMPOSE_FILE) as f:
            config = yaml.safe_load(f)

        for svc_name, svc in config.get("services", {}).items():
            build = svc.get("build")
            if build is None:
                continue

            if isinstance(build, str):
                context = build
                dockerfile = "Dockerfile"
            elif isinstance(build, dict):
                context = build.get("context", ".")
                dockerfile = build.get("dockerfile", "Dockerfile")
            else:
                continue

            dockerfile_path = PROJECT_ROOT / context / dockerfile
            assert dockerfile_path.exists(), \
                f"Service {svc_name}: Dockerfile not found at {dockerfile_path}"
