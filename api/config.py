"""Application configuration using Pydantic settings."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """NHI Security Testbed API configuration."""

    app_name: str = "NHI Security Testbed API"
    version: str = "0.1.0"
    debug: bool = False

    # Wazuh API connection
    wazuh_api_url: str = "https://wazuh.manager:55000"
    wazuh_api_user: str = "wazuh-wui"
    wazuh_api_password: str = "MyS3cr3tP@ssw0rd"
    wazuh_verify_ssl: bool = False

    # Container runtime
    container_runtime: str = "docker"

    # Scenario and rule paths (inside the container)
    scenarios_dir: str = "/app/scenarios"
    rules_file: str = "/app/wazuh/rules/nhi-detection-rules.xml"
    decoders_file: str = "/app/wazuh/decoders/nhi-decoders.xml"

    # Alert validation
    validation_poll_interval: int = 3
    validation_max_wait: int = 30

    model_config = {"env_prefix": "NHI_"}


settings = Settings()
