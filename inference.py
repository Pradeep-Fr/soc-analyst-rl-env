"""
SOC Analyst Environment — Baseline Inference Script
=====================================================

Runs an LLM agent against all 3 tasks (soc_easy, soc_medium, soc_hard)
and outputs structured logs in the mandatory [START]/[STEP]/[END] format.

Environment variables:
    API_BASE_URL   - LLM API endpoint (default: HuggingFace router)
    MODEL_NAME     - Model identifier (default: Qwen/Qwen2.5-72B-Instruct)
    HF_TOKEN       - HuggingFace API key
    SOC_ENV_URL    - URL of the running SOC Analyst env server

STDOUT FORMAT:
    [START] task=<task_name> env=soc_analyst_env model=<model_name>
    [STEP]  step=<n> action=<action_str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> score=<score> rewards=<r1,r2,...>
"""

import json
import os
import textwrap
from typing import List, Optional

import requests
from openai import OpenAI

# ─── Configuration ───────────────────────────────────────────────────────────

API_KEY = os.getenv("HF_TOKEN") or os.getenv("API_KEY")
API_BASE_URL = os.getenv("API_BASE_URL") or "https://router.huggingface.co/v1"
MODEL_NAME = os.getenv("MODEL_NAME") or "Qwen/Qwen2.5-72B-Instruct"
ENV_URL = os.getenv("SOC_ENV_URL") or "http://localhost:8000"

TASKS = ["soc_easy", "soc_medium", "soc_hard"]
BENCHMARK = "soc_analyst_env"
MAX_STEPS = 30  # Hard task has 25 events, give some headroom
TEMPERATURE = 0.2  # Low temp for consistency
MAX_TOKENS = 200

SYSTEM_PROMPT = textwrap.dedent("""
You are an expert SOC (Security Operations Center) analyst. You are processing
a stream of security events and must triage each one.

For each event, you MUST respond with EXACTLY one of these four actions:
  PERMIT  — Normal activity, no action needed
  VERIFY  — Soft lock: remove write permissions, trigger MFA
  SUSPEND — Disable account, requires human review / appeal
  BAN     — Immediate termination of all sessions, IP blacklist

Decision guidelines based on MITRE ATT&CK threat tiers:

TIER 1 CRITICAL → BAN:
  - Ransomware: commands like "vssadmin delete shadows", "wmic shadowcopy delete",
    PowerShell encoded shadow copy deletion
  - Credential harvesting: mimikatz, lsass.exe dumps (procdump, comsvcs.dll MiniDump),
    ntdsutil IFM dumps, SAM registry hive exports (reg save HKLM\\SAM)

TIER 2 HIGH → SUSPEND:
  - Impossible travel: login from two distant cities within physically impossible time
  - Brute force: 100+ consecutive failed logins followed by a success

TIER 3 MEDIUM → VERIFY:
  - First-time / unregistered device combined with bulk download (>1GB)
  - Login outside the user's typical business hours
  - Suspicious combinations of after-hours + unregistered device

BENIGN → PERMIT:
  - Normal work activity during business hours from registered devices
  - IT Administrators running legitimate commands (e.g., "vssadmin list shadows",
    "tasklist" to view processes — NOT delete/dump)
  - Users with few failed logins (<20) from their usual location (password forgotten)
  - Remote workers with consistent location (both logins from same foreign city)
  - New employees downloading onboarding materials from registered devices
  - Data engineers doing scheduled backups from registered devices

CRITICAL NUANCES:
  - "vssadmin LIST shadows" (read-only) is BENIGN, "vssadmin DELETE shadows" is BAN
  - "tasklist" viewing lsass info is BENIGN, "procdump lsass" is BAN
  - 5-8 failed logins from usual location = forgotten password → PERMIT
  - 100+ failed logins = brute force → SUSPEND
  - Large downloads FROM a registered device by a Data Engineer = PERMIT
  - Large downloads TO an unregistered device = VERIFY

Respond with ONLY the action word. No explanation, no extra text.
""").strip()


# ─── Logging Helpers ─────────────────────────────────────────────────────────

def log_start(task: str, env: str, model: str) -> None:
    print(f"[START] task={task} env={env} model={model}", flush=True)


def log_step(step: int, action: str, reward: float, done: bool, error: Optional[str]) -> None:
    error_val = error if error else "null"
    done_val = str(done).lower()
    print(
        f"[STEP] step={step} action={action} reward={reward:.2f} done={done_val} error={error_val}",
        flush=True,
    )


def log_end(success: bool, steps: int, score: float, rewards: List[float]) -> None:
    rewards_str = ",".join(f"{r:.2f}" for r in rewards)
    print(
        f"[END] success={str(success).lower()} steps={steps} score={score:.2f} rewards={rewards_str}",
        flush=True,
    )


# ─── Environment Interface (HTTP) ───────────────────────────────────────────

def env_reset(task_name: str) -> dict:
    """Reset the environment for a specific task via HTTP POST."""
    resp = requests.post(
        f"{ENV_URL}/reset",
        json={"task_name": task_name},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


def env_step(action: str) -> dict:
    """Take a step in the environment via HTTP POST."""
    resp = requests.post(
        f"{ENV_URL}/step",
        json={"action": action},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


# ─── LLM Agent ──────────────────────────────────────────────────────────────

def build_event_prompt(obs: dict) -> str:
    """Build a user prompt from observation data."""
    o = obs.get("observation", obs)
    return textwrap.dedent(f"""
SECURITY EVENT #{o.get('event_id', '?')}/{o.get('total_events', '?')}

User: {o.get('user_id', 'N/A')}
  Role: {o.get('job_role', 'N/A')} | Department: {o.get('department', 'N/A')}
  Typical Hours: {o.get('typical_login_hours', 'N/A')}
  Registered Devices: {', '.join(o.get('registered_devices', [])) or 'N/A'}

Event:
  Timestamp: {o.get('timestamp', 'N/A')}
  Source IP: {o.get('source_ip', 'N/A')}
  Location: {o.get('geo_location', 'N/A')}
  Action: {o.get('action_string', 'N/A')}
  Payload Size: {o.get('payload_size_mb', 0):.1f} MB
  Device: {o.get('device_id', 'N/A')}
  Failed Logins Before This: {o.get('failed_login_count', 0)}
  Previous Login: {o.get('previous_login_location', 'N/A')} at {o.get('previous_login_timestamp', 'N/A')}

Feedback from last decision: {o.get('message', 'N/A')}

What is your triage decision? Reply with EXACTLY one word: PERMIT, VERIFY, SUSPEND, or BAN.
    """).strip()


def get_agent_action(client: OpenAI, obs: dict, history: List[dict]) -> str:
    """Get the LLM's triage decision."""
    user_prompt = build_event_prompt(obs)

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    # Add recent history for context (last 4 exchanges)
    messages.extend(history[-8:])
    messages.append({"role": "user", "content": user_prompt})

    try:
        completion = client.chat.completions.create(
            model=MODEL_NAME,
            messages=messages,
            temperature=TEMPERATURE,
            max_tokens=MAX_TOKENS,
            stream=False,
        )
        raw = (completion.choices[0].message.content or "").strip().upper()

        # Parse action from response — handle cases where model adds explanation
        for valid_action in ["BAN", "SUSPEND", "VERIFY", "PERMIT"]:
            if valid_action in raw:
                return valid_action

        # Default fallback
        return "PERMIT"

    except Exception as exc:
        print(f"[DEBUG] Model request failed: {exc}", flush=True)
        return "PERMIT"


# ─── Main Loop ──────────────────────────────────────────────────────────────

def run_task(client: OpenAI, task_name: str) -> float:
    """Run a single task and return the normalized score [0, 1]."""

    history: List[dict] = []
    rewards: List[float] = []
    steps_taken = 0
    score = 0.0
    success = False

    log_start(task=task_name, env=BENCHMARK, model=MODEL_NAME)

    try:
        # Reset environment
        reset_resp = env_reset(task_name)
        obs = reset_resp
        done = reset_resp.get("done", False)

        for step in range(1, MAX_STEPS + 1):
            if done:
                break

            # Get agent decision
            action = get_agent_action(client, obs, history)

            # Take step
            step_resp = env_step(action)
            obs = step_resp
            reward = step_resp.get("reward") or 0.0
            done = step_resp.get("done", False)
            error = None

            rewards.append(reward)
            steps_taken = step

            log_step(step=step, action=action, reward=reward, done=done, error=error)

            # Update history
            user_prompt = build_event_prompt(obs)
            history.append({"role": "user", "content": user_prompt})
            history.append({"role": "assistant", "content": action})

            if done:
                break

        # Compute normalized score [0, 1]
        total_events = steps_taken if steps_taken > 0 else 1
        raw_score = sum(rewards)
        max_possible = total_events * 1.0
        score = max(0.0, raw_score) / max_possible if max_possible > 0 else 0.0
        score = min(max(score, 0.0), 1.0)
        success = score >= 0.5  # At least half correct

    except Exception as exc:
        print(f"[DEBUG] Task {task_name} failed: {exc}", flush=True)

    finally:
        log_end(success=success, steps=steps_taken, score=score, rewards=rewards)

    return score


def main():
    """Run inference on all 3 tasks."""
    client = OpenAI(base_url=API_BASE_URL, api_key=API_KEY)

    scores = {}
    for task in TASKS:
        score = run_task(client, task)
        scores[task] = score
        print(f"\n{'='*60}", flush=True)

    # Summary
    print(f"\n{'='*60}", flush=True)
    print("BASELINE RESULTS SUMMARY", flush=True)
    print(f"{'='*60}", flush=True)
    for task, score in scores.items():
        print(f"  {task}: {score:.3f}", flush=True)
    avg = sum(scores.values()) / len(scores) if scores else 0
    print(f"  AVERAGE: {avg:.3f}", flush=True)
    print(f"{'='*60}", flush=True)


if __name__ == "__main__":
    main()
