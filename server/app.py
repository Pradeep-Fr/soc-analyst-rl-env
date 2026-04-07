"""
FastAPI application for the SOC Analyst Environment.

Endpoints:
    - POST /reset: Reset the environment
    - POST /step: Execute an action
    - GET /state: Get current environment state
    - GET /schema: Get action/observation schemas
    - WS /ws: WebSocket endpoint for persistent sessions
"""

import os
import sys
from pathlib import Path

# Ensure the project root is in sys.path for absolute imports
ROOT_DIR = Path(__file__).parent.parent.absolute()
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    from openenv.core.env_server.http_server import create_app
except Exception as e:
    raise ImportError(
        "openenv is required. Install with: pip install openenv-core[core]"
    ) from e

try:
    from ..models import SocAnalystAction, SocAnalystObservation
    from .soc_analyst_env_environment import SocAnalystEnvironment
except (ImportError, ValueError, ModuleNotFoundError):
    try:
        from models import SocAnalystAction, SocAnalystObservation
        from server.soc_analyst_env_environment import SocAnalystEnvironment
    except ImportError:
        from soc_analyst_env.models import SocAnalystAction, SocAnalystObservation
        from soc_analyst_env.server.soc_analyst_env_environment import SocAnalystEnvironment



# Read task from env var (allows switching at deploy time)
DEFAULT_TASK = os.getenv("SOC_TASK", "soc_easy")


def _env_factory():
    """Create a new environment instance with the default task."""
    return SocAnalystEnvironment(task_name=DEFAULT_TASK)


# Create the app with web interface
app = create_app(
    _env_factory,
    SocAnalystAction,
    SocAnalystObservation,
    env_name="soc_analyst_env",
    max_concurrent_envs=4,
)


def main(host: str = "0.0.0.0", port: int = 8000):
    """Entry point for direct execution."""
    import uvicorn
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    main(port=args.port)
