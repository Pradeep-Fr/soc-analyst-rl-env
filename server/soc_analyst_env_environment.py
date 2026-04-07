"""
SOC Analyst Environment Implementation.

Simulates a Security Operations Center where an AI agent processes a stream
of security events and must decide whether to PERMIT, VERIFY, SUSPEND, or BAN.

Reward design follows MITRE ATT&CK threat tiers:
  - Correct action → +1.0
  - Close but wrong → -0.3 to -0.5
  - Dangerously wrong → -1.0
  - Business disruption (banning innocent users) → -1.0
"""

import sys
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

# Ensure the project root is in sys.path for absolute imports
ROOT_DIR = Path(__file__).parent.parent.absolute()
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    # Try relative imports (works when run as a package: python -m soc_analyst_env.server.app)
    from ..models import SocAnalystAction, SocAnalystObservation, ActionType
    from ..scenarios import TASK_EVENTS, SecurityEvent
except (ImportError, ValueError):
    # Fallback to absolute imports (works when run as a script or from the project root)
    try:
        from models import SocAnalystAction, SocAnalystObservation, ActionType
        from scenarios import TASK_EVENTS, SecurityEvent
    except ImportError:
        # Last resort: try namespaced imports if the parent directory is in the path
        from soc_analyst_env.models import SocAnalystAction, SocAnalystObservation, ActionType
        from soc_analyst_env.scenarios import TASK_EVENTS, SecurityEvent



# =============================================================================
# Reward Matrix
# =============================================================================

# Reward for (correct_action, agent_action) pairs
# Rows = correct_action, Cols = agent_action
REWARD_MATRIX = {
    # Correct action is BAN (TIER 1 CRITICAL)
    "BAN": {
        "BAN":     +1.0,    # Perfect
        "SUSPEND": -0.5,    # Under-reacted — threat still active
        "VERIFY":  -0.8,    # Dangerous under-reaction
        "PERMIT":  -1.0,    # Catastrophic — let ransomware/credential theft proceed
    },
    # Correct action is SUSPEND (TIER 2 HIGH)
    "SUSPEND": {
        "BAN":     -0.5,    # Over-reacted — too aggressive for context
        "SUSPEND": +1.0,    # Perfect
        "VERIFY":  -0.3,    # Under-reacted but not catastrophic
        "PERMIT":  -1.0,    # Dangerous — brute force / impossible travel ignored
    },
    # Correct action is VERIFY (TIER 3 MEDIUM)
    "VERIFY": {
        "BAN":     -1.0,    # Way too aggressive — bad UX, false positive
        "SUSPEND": -0.5,    # Over-reacted
        "VERIFY":  +1.0,    # Perfect
        "PERMIT":  -0.5,    # Under-reacted — insider threat/unusual activity ignored
    },
    # Correct action is PERMIT (BENIGN)
    "PERMIT": {
        "BAN":     -1.0,    # Worst: banned an innocent user
        "SUSPEND": -0.7,    # Bad: suspended innocent user
        "VERIFY":  -0.3,    # Overcautious but acceptable
        "PERMIT":  +1.0,    # Perfect
    },
}


def compute_reward(correct_action: str, agent_action: str) -> float:
    """Compute reward for an agent action given the correct action."""
    return REWARD_MATRIX.get(correct_action, {}).get(agent_action, -1.0)


class SocAnalystEnvironment(Environment):
    """
    SOC Analyst Environment.

    The agent receives a stream of security events and must triage each one
    by choosing PERMIT, VERIFY, SUSPEND, or BAN. Rewards are based on
    MITRE ATT&CK-aligned ground truth rules.

    Tasks:
      - soc_easy: 10 events, obvious threats, no tricks
      - soc_medium: 15 events, context-dependent with benign traps
      - soc_hard: 25 events, alert fatigue + adaptive attacker
    """

    SUPPORTS_CONCURRENT_SESSIONS: bool = True

    def __init__(self, task_name: str = "soc_easy"):
        """Initialize the SOC Analyst environment.

        Args:
            task_name: One of 'soc_easy', 'soc_medium', 'soc_hard'
        """
        super().__init__()
        if task_name not in TASK_EVENTS:
            raise ValueError(
                f"Unknown task: {task_name}. Choose from: {list(TASK_EVENTS.keys())}"
            )
        self._task_name = task_name
        self._events = TASK_EVENTS[task_name]
        self._current_event_idx = 0
        self._cumulative_reward = 0.0
        self._rewards: list[float] = []
        self._state = State(episode_id=str(uuid4()), step_count=0)

    def _event_to_observation(
        self,
        event: SecurityEvent,
        idx: int,
        done: bool = False,
        reward: float = 0.0,
        message: str = "",
    ) -> SocAnalystObservation:
        """Convert a SecurityEvent to an Observation."""
        return SocAnalystObservation(
            # Event metadata
            event_id=idx + 1,
            total_events=len(self._events),
            # User metadata
            user_id=event.user_id,
            job_role=event.job_role,
            department=event.department,
            typical_login_hours=event.typical_login_hours,
            registered_devices=event.registered_devices,
            # Current event
            timestamp=event.timestamp,
            source_ip=event.source_ip,
            geo_location=event.geo_location,
            action_string=event.action_string,
            payload_size_mb=event.payload_size_mb,
            device_id=event.device_id,
            failed_login_count=event.failed_login_count,
            previous_login_location=event.previous_login_location,
            previous_login_timestamp=event.previous_login_timestamp,
            # Environment state
            task_name=self._task_name,
            events_remaining=len(self._events) - idx - 1,
            cumulative_reward=self._cumulative_reward,
            message=message,
            # Base fields
            done=done,
            reward=reward,
            metadata={
                "event_index": idx,
                "step": self._state.step_count,
            },
        )

    def reset(
        self,
        seed: Optional[int] = None,
        episode_id: Optional[str] = None,
        **kwargs: Any,
    ) -> SocAnalystObservation:
        """Reset the environment and return the first security event.

        Args:
            seed: Ignored (events are deterministic)
            episode_id: Optional custom episode ID

        Returns:
            Observation containing the first security event
        """
        # Handle task_name override from kwargs or reset params
        task_name = kwargs.get("task_name", self._task_name)
        if task_name in TASK_EVENTS:
            self._task_name = task_name
            self._events = TASK_EVENTS[task_name]

        self._current_event_idx = 0
        self._cumulative_reward = 0.0
        self._rewards = []
        self._state = State(
            episode_id=episode_id or str(uuid4()),
            step_count=0,
        )

        first_event = self._events[0]
        return self._event_to_observation(
            first_event,
            idx=0,
            done=False,
            reward=0.0,
            message=f"SOC Analyst shift started. Task: {self._task_name}. "
                    f"You will process {len(self._events)} security events. "
                    f"Choose PERMIT, VERIFY, SUSPEND, or BAN for each event.",
        )

    def step(
        self,
        action: SocAnalystAction,
        timeout_s: Optional[float] = None,
        **kwargs: Any,
    ) -> SocAnalystObservation:
        """Process the agent's triage decision and advance to the next event.

        Args:
            action: The agent's triage decision (PERMIT/VERIFY/SUSPEND/BAN)

        Returns:
            Observation with the next event (or done=True if episode is over)
        """
        self._state.step_count += 1

        # Get current event and compute reward
        current_event = self._events[self._current_event_idx]
        agent_action = action.action.value
        reward = compute_reward(current_event.correct_action, agent_action)

        self._cumulative_reward += reward
        self._rewards.append(reward)

        # Build feedback message
        is_correct = agent_action == current_event.correct_action
        feedback = (
            f"Event {self._current_event_idx + 1}/{len(self._events)}: "
            f"You chose {agent_action}. "
        )
        if is_correct:
            feedback += f"Correct! {current_event.explanation}"
        else:
            feedback += (
                f"Wrong — correct action was {current_event.correct_action}. "
                f"{current_event.explanation}"
            )

        # Advance to next event
        self._current_event_idx += 1
        is_done = self._current_event_idx >= len(self._events)

        if is_done:
            # Episode complete — return final observation
            max_possible = len(self._events) * 1.0
            score = max(0.0, self._cumulative_reward) / max_possible
            score = min(max(score, 0.0), 1.0)

            feedback += (
                f" | SHIFT COMPLETE. "
                f"Final score: {score:.3f} "
                f"({sum(1 for r in self._rewards if r > 0)}/{len(self._rewards)} correct)"
            )

            return SocAnalystObservation(
                event_id=self._current_event_idx,
                total_events=len(self._events),
                user_id="",
                job_role="",
                department="",
                typical_login_hours="",
                registered_devices=[],
                timestamp="",
                source_ip="",
                geo_location="",
                action_string="",
                payload_size_mb=0.0,
                device_id="",
                failed_login_count=0,
                previous_login_location="",
                previous_login_timestamp="",
                task_name=self._task_name,
                events_remaining=0,
                cumulative_reward=self._cumulative_reward,
                message=feedback,
                done=True,
                reward=reward,
                metadata={
                    "event_index": self._current_event_idx - 1,
                    "step": self._state.step_count,
                    "final_score": score,
                    "total_correct": sum(1 for r in self._rewards if r > 0),
                    "total_events": len(self._events),
                    "all_rewards": self._rewards,
                },
            )
        else:
            # Return next event
            next_event = self._events[self._current_event_idx]
            return self._event_to_observation(
                next_event,
                idx=self._current_event_idx,
                done=False,
                reward=reward,
                message=feedback,
            )

    @property
    def state(self) -> State:
        """Get the current environment state."""
        return self._state

    def get_metadata(self):
        """Return environment metadata for the web interface."""
        from openenv.core.env_server.types import EnvironmentMetadata
        return EnvironmentMetadata(
            name="SOC Analyst",
            description=(
                "Security Operations Center analyst environment. "
                "Triage security events by choosing PERMIT, VERIFY, SUSPEND, or BAN. "
                "Based on MITRE ATT&CK threat signatures."
            ),
            version="1.0.0",
        )
