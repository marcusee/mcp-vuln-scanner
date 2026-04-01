"""Configuration for the vulnerability remediation MCP server."""
 
from __future__ import annotations
 
import os
from dataclasses import dataclass, field
 
 
@dataclass
class Settings:
    """Server settings loaded from environment variables."""
 
    # Server identity
    service_name: str = "vuln-remediation"
 
    # Transport
    transport: str = "stdio"
    host: str = "0.0.0.0"
    port: int = 8080
 
    # Data paths
    sarif_path: str = "./data/scan_results.sarif.json"
    project_root: str = "./vulnerable_app"
 
    # Operational
    stage: str = "poc"
    advisory_only: bool = True
 
    @classmethod
    def from_env(cls) -> Settings:
        """Load settings from environment variables."""
        return cls(
            service_name=os.environ.get("SERVICE_NAME", cls.service_name),
            transport=os.environ.get("MCP_TRANSPORT", cls.transport),
            host=os.environ.get("MCP_HOST", cls.host),
            port=int(os.environ.get("MCP_PORT", str(cls.port))),
            sarif_path=os.environ.get("SARIF_PATH", cls.sarif_path),
            project_root=os.environ.get("PROJECT_ROOT", cls.project_root),
            stage=os.environ.get("STAGE", cls.stage),
            advisory_only=os.environ.get("ADVISORY_ONLY", "true").lower() == "true",
        )
 