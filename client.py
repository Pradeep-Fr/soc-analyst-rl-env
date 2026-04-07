"""SOC Analyst Environment Client."""

from typing import Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

from .models import SocAnalystAction, SocAnalystObservation


class SocAnalystEnv(
    EnvClient[SocAnalystAction, SocAnalystObservation, State]
):
    """
    Client for the SOC Analyst Environment.

    Example:
        >>> async with SocAnalystEnv(base_url="http://localhost:8000") as env:
        ...     result = await env.reset()
        ...     while not result.done:
        ...         action = SocAnalystAction(action="PERMIT")
        ...         result = await env.step(action)
    """

    def _step_payload(self, action: SocAnalystAction) -> Dict:
        """Convert action to JSON payload."""
        return {"action": action.action.value}

    def _parse_result(self, payload: Dict) -> StepResult[SocAnalystObservation]:
        """Parse server response into StepResult."""
        obs_data = payload.get("observation", {})
        observation = SocAnalystObservation(**obs_data)

        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict) -> State:
        """Parse state response."""
        return State(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
        )
