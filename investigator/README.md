# investigator

The investigator diagnoses an incident remotely, without the customer, following DESIGN.md §10. It combines a fleet
differential diagnosis with a hypothesis and probe loop, and runs on the backend's internal network.

| Module | Role |
| --- | --- |
| `fleet_diff.py` | Classifies symptoms (network, permission, crash by signature, hang, resource). Computes the lift of every attribute value over the fleet, with a minimum support of 5 endpoints. |
| `evidence.py` | Turns probe outputs into facts. For example, `net.synthetic_tls` gives the leaf issuer per path, and an issuer mismatch means interception. |
| `reasoners.py` | `RuleReasoner` (offline), `ClaudeReasoner` (Anthropic SDK) and `ReplayReasoner`. All three share one JSON schema. |
| `loop.py` | Triage, then hypothesize, then a policy pre-check, then probes, then update. Stops at confidence ≥ 0.8, when the reasoner is done, or after 3 rounds. |
| `report.py` | Renders the report as Markdown. The CLI also stores the report in the control plane (`/v1/admin/reports`). |

**The LLM proposes, the policy decides.** Probe IDs come from a fixed allowlist (`net.config`, `net.synthetic_tls`,
`env.extensions`, `svc.launchctl`) and are never commands. A proposal passes three checks before anything runs:
1. **Local pre-check:** the allowlist, no repeats, and a budget of 4 probes per incident.
2. **Control plane:** the allowlist again, the incident's own endpoint only, and the budget. It then signs the
   request with ECDSA P-256 and a TTL of 120 s.
3. **Endpoint:** the signature against the pinned key, the endpoint id, the expiry, a replay check, and its own
   budget.

Refused probes are reported back with a reason.

## Run

The investigator runs as a compose service on the backend network. The control plane's port 8000 is never
published.

```sh
cd backend
docker compose --profile tools run --rm sim                                   # import the simulated fleet
docker compose --profile tools run --rm investigator investigate --latest --endpoint ep-demo
docker compose --profile tools run --rm investigator investigate --incident <id> --reasoner rule --json
docker compose --profile tools run --rm investigator doctor [--live]
docker compose --profile watch up -d investigator-watch                      # always on: every new incident
```

`--reasoner` takes one of:
- `auto` (the default): Claude when `ANTHROPIC_API_KEY` is set, otherwise rules;
- `claude`;
- `rule`;
- `replay`, with `--recording FILE`.

`--record FILE`, in claude mode, saves the session for replay. The full scripted demo is
`scripts/e2e_investigation.sh`.

## Claude and the API key

- **Model and call:** the model is `claude-opus-5-5`; override it with `IESO_CLAUDE_MODEL`. Each round is one
  `client.beta.messages.create` call:
  - structured output (`output_config.format` with the decision JSON schema) and `effort: high`;
  - thinking stays on (adaptive, the model's default);
  - server-side refusal fallbacks (`fallbacks: "default"`).
- **Validation:** the output is checked again locally against the schema and value ranges.
- **Fallback:** an API error, a refusal, truncation or invalid output falls back to the rule reasoner for that
  round, and the report says so (`claude (...) with rule fallback`).
- **What Claude sees:** only sanitized data that already passed the endpoint's PII filter: the incident, the fleet
  statistics and the probe facts.
- **The key:** it's read from the `ANTHROPIC_API_KEY` environment variable only, through your shell or through
  `backend/.env`, which is gitignored (copy `backend/.env.example`). It's never logged, printed or written to a
  recording. `doctor` reports only whether it is set.

On the host, for development:

```sh
python3 -m venv investigator/.venv && investigator/.venv/bin/pip install -r investigator/requirements-dev.txt
cd investigator && .venv/bin/python -m pytest -q
```

## Replay recordings

`recordings/network-tls-interception.json` is a real Claude session. It holds:
- the sanitized context sent each round;
- the prompt;
- the raw response text;
- the validated decision;
- the model and the date.

It's created by running with a key:

```sh
ANTHROPIC_API_KEY=... IESO_RECORD=1 scripts/e2e_investigation.sh
```

Replay plays the decisions back in order and makes no API call. The control plane, signing, the endpoint and the
probes all still run live. Reports from a replay are labeled `claude (replayed recording, <model>, <date>)`.

`tests/fixtures/replay_fixture.json` is a hand-written test fixture, and it's marked as such. It isn't a Claude
output.
