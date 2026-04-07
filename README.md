---
title: SOC Analyst Environment
emoji: 🛡️
colorFrom: red
colorTo: indigo
sdk: docker
pinned: false
app_port: 8000
base_path: /web
tags:
  - openenv
---

# 🛡️ SOC Analyst Environment

A realistic Security Operations Center (SOC) analyst environment for training and evaluating AI agents on **security event triage** — deciding whether to PERMIT, VERIFY, SUSPEND, or BAN based on MITRE ATT&CK-aligned threat signatures.

## Why This Environment?

SOC analysts process thousands of security alerts per shift. Alert fatigue causes real analysts to miss critical threats — an estimated **30% of alerts go uninvestigated** (Ponemon Institute). This environment models that exact challenge:

- **Real-world task**: Security event triage is performed by >400,000 SOC analysts worldwide
- **Business-aware decisions**: The agent must balance security (catching threats) with business impact (not banning innocent users)
- **MITRE ATT&CK alignment**: All threat signatures map to real-world attack techniques

## Environment Description

The agent plays the role of a SOC analyst processing a **stream of security events** during a shift. Each event contains:

- **User metadata**: job role, department, typical login hours, registered devices
- **Event data**: timestamp, source IP, geolocation, action string (command/activity), payload size, device ID, login history

The agent must classify each event into one of four response levels.

## Action Space

| Action | Description | Use Case |
|--------|-------------|----------|
| `PERMIT` | Allow activity | Normal behavior, routine operations |
| `VERIFY` | Soft lock — trigger MFA, remove write access | Unusual but not dangerous (after-hours login, new device) |
| `SUSPEND` | Disable account, require human review | Serious threat indicators (impossible travel, brute force) |
| `BAN` | Kill all sessions, blacklist IP | Critical threats (ransomware, credential theft) |

## Observation Space

```json
{
    "event_id": 1,
    "total_events": 10,
    "user_id": "USR-1042",
    "job_role": "Contractor",
    "department": "External",
    "typical_login_hours": "09:00-17:00",
    "registered_devices": ["DEV-WIN-8821"],
    "timestamp": "2025-03-15T14:22:31Z",
    "source_ip": "198.51.100.45",
    "geo_location": "Unknown VPN Exit Node",
    "action_string": "vssadmin delete shadows /all /quiet",
    "payload_size_mb": 0.01,
    "device_id": "DEV-WIN-8821",
    "failed_login_count": 0,
    "previous_login_location": "New York, US",
    "previous_login_timestamp": "2025-03-15T09:01:00Z",
    "task_name": "soc_easy",
    "events_remaining": 9,
    "cumulative_reward": 0.0,
    "message": "SOC Analyst shift started...",
    "done": false,
    "reward": 0.0
}
```

## Tasks

### `soc_easy` — 10 events (Easy)
Obvious threats with clear signatures. No ambiguity or traps. Tests basic pattern recognition.

- Ransomware commands (`vssadmin delete shadows`, LSASS dumps)
- Clear impossible travel (London → Tokyo in 25 min)
- Standard brute force (127 failed logins)
- Normal work activities (git push, opening spreadsheets)

### `soc_medium` — 15 events (Medium)
Context-dependent decisions with **benign traps** mixed in:

- IT Admin running `vssadmin list shadows` (legitimate — NOT ransomware)
- Employee who forgot password with 5 failed logins (NOT brute force)
- Remote worker on vacation logging in from Berlin (NOT impossible travel)
- New employee downloading 1.5GB onboarding materials (NOT insider threat)

### `soc_hard` — 25 events (Hard)
**Alert fatigue + adaptive attacker**:

- First 14 events are mostly benign (lulls the agent into always saying PERMIT)
- Threats use adapted signatures:
  - `wmic shadowcopy delete` instead of `vssadmin delete shadows`
  - `ntdsutil IFM dump` instead of `mimikatz`
  - Base64-encoded PowerShell shadow copy deletion
  - `reg save HKLM\SAM` for offline credential cracking
- Heavy false positive traps (Data Engineer doing 15GB backup, IT Admin viewing LSASS process info)

## Reward Design

| Scenario | Reward |
|----------|--------|
| ✅ Correct decision | `+1.0` |
| ⚠️ Close but wrong (e.g., VERIFY instead of SUSPEND) | `-0.3` |
| ❌ Missed real threat (PERMIT on ransomware) | `-1.0` |
| 🚫 Banned innocent user | `-1.0` |
| ⬆️ Over-escalated minor issue | `-0.5` to `-0.7` |

**Key design principle**: False positives (banning innocent users) are penalized equally to false negatives (missing threats). This forces the agent to be _Business-aware_, not just a "ban everything" filter.

Final score per task = `max(0, cumulative_reward) / total_events`, clamped to [0.0, 1.0].

## Setup & Usage

### Docker (Recommended)

```bash
# Build
cd soc_analyst_env
docker build -t soc-analyst-env:latest .

# Run
docker run -p 8000:8000 soc-analyst-env:latest
```

### Local Development

```bash
cd soc_analyst_env
pip install -r server/requirements.txt
uvicorn server.app:app --reload --host 0.0.0.0 --port 8000
```

### Running the Baseline

```bash
# Set your API credentials
export HF_TOKEN="your-token-here"
export API_BASE_URL="https://router.huggingface.co/v1"
export MODEL_NAME="Qwen/Qwen2.5-72B-Instruct"

# Start the environment server
uvicorn server.app:app --host 0.0.0.0 --port 8000 &

# Run inference
python inference.py
```

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/reset` | POST | Reset environment (accepts `task_name` in body) |
| `/step` | POST | Submit action (`{"action": {"action": "BAN"}}`) |
| `/state` | GET | Get current state |
| `/schema` | GET | Get action/observation JSON schemas |
| `/health` | GET | Health check |
| `/ws` | WS | WebSocket for persistent sessions |

## Project Structure

```
soc_analyst_env/
├── Dockerfile              # Container for HF Spaces
├── README.md               # This file
├── openenv.yaml            # OpenEnv manifest
├── pyproject.toml          # Project metadata
├── inference.py            # Baseline inference script
├── __init__.py             # Package exports
├── models.py               # Pydantic Action/Observation models
├── scenarios.py            # Security event data (50 events)
├── client.py               # EnvClient for programmatic access
└── server/
    ├── __init__.py
    ├── app.py              # FastAPI application
    ├── requirements.txt    # Docker dependencies
    └── soc_analyst_env_environment.py  # Core environment logic
```

## Baseline Scores

| Task | Score | Notes |
|------|-------|-------|
| `soc_easy` | ~0.90 | Most models handle obvious signatures well |
| `soc_medium` | ~0.65 | Benign traps catch over-aggressive models |
| `soc_hard` | ~0.45 | Alert fatigue and adapted signatures challenge even strong models |

## Creativity & Novelty

- **Alert fatigue simulation**: Tests if agents stay vigilant after long benign sequences
- **Adaptive attacker**: Hard task uses variant signatures (wmic, ntdsutil, encoded PowerShell) that test generalization beyond exact pattern matching
- **Business friction penalty**: Over-banning is equally bad as under-responding — forces nuanced decision-making
- **MITRE ATT&CK alignment**: Real-world relevance backed by industry-standard threat taxonomy
