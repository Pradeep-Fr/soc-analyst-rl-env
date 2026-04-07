"""
Data models for the SOC Analyst Environment.

The soc_analyst environment simulates a Security Operations Center where
an AI agent triages security events from a stream, deciding whether to
PERMIT, VERIFY, SUSPEND, or BAN based on MITRE ATT&CK-aligned signatures.
"""

from enum import Enum
from typing import Dict, List, Optional

from openenv.core.env_server.types import Action, Observation
from pydantic import Field


class ActionType(str, Enum):
    """Available actions the SOC analyst agent can take."""
    PERMIT = "PERMIT"
    VERIFY = "VERIFY"
    SUSPEND = "SUSPEND"
    BAN = "BAN"


class SocAnalystAction(Action):
    """Action for the SOC Analyst environment.

    The agent must choose one of four responses to each security event:
    - PERMIT: Allow the activity (normal behavior)
    - VERIFY: Soft lock - remove write permissions and trigger MFA
    - SUSPEND: Account disabled, requires human review
    - BAN: Immediate termination of all sessions and IP blacklisting
    """
    action: ActionType = Field(
        ...,
        description="The triage decision: PERMIT, VERIFY, SUSPEND, or BAN",
    )


class SocAnalystObservation(Observation):
    """Observation from the SOC Analyst environment.

    Presents a security event with user metadata and event details for
    the agent to analyze and classify.
    """

    # --- Event metadata ---
    event_id: int = Field(
        default=0,
        description="Sequential ID of the current event in the stream",
    )
    total_events: int = Field(
        default=0,
        description="Total number of events in this episode",
    )

    # --- User metadata ---
    user_id: str = Field(
        default="",
        description="Unique identifier for the user who generated the event",
    )
    job_role: str = Field(
        default="",
        description="User's job role (e.g., Engineer, IT Admin, Analyst)",
    )
    department: str = Field(
        default="",
        description="User's department (e.g., Engineering, Finance, IT)",
    )
    typical_login_hours: str = Field(
        default="",
        description="User's normal login window, e.g., '09:00-18:00'",
    )
    registered_devices: List[str] = Field(
        default_factory=list,
        description="List of device identifiers registered to the user",
    )

    # --- Current event ---
    timestamp: str = Field(
        default="",
        description="ISO-8601 timestamp of when the event occurred",
    )
    source_ip: str = Field(
        default="",
        description="IP address of the request origin",
    )
    geo_location: str = Field(
        default="",
        description="Geographic location inferred from IP (city, country)",
    )
    action_string: str = Field(
        default="",
        description="The raw action/command string observed (e.g., 'vssadmin delete shadows')",
    )
    payload_size_mb: float = Field(
        default=0.0,
        description="Size of the data payload in megabytes",
    )
    device_id: str = Field(
        default="",
        description="Identifier of the device used for this event",
    )
    failed_login_count: int = Field(
        default=0,
        description="Number of consecutive failed logins before this event",
    )
    previous_login_location: str = Field(
        default="",
        description="Location of the user's last successful login",
    )
    previous_login_timestamp: str = Field(
        default="",
        description="Timestamp of the user's last successful login",
    )

    # --- Environment state ---
    task_name: str = Field(
        default="",
        description="Name of the current task (soc_easy, soc_medium, soc_hard)",
    )
    events_remaining: int = Field(
        default=0,
        description="Number of events remaining in this episode",
    )
    cumulative_reward: float = Field(
        default=0.0,
        description="Sum of rewards earned so far",
    )
    message: str = Field(
        default="",
        description="Human-readable context or feedback message",
    )
