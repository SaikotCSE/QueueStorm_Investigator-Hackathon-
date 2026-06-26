# QueueStorm Investigator

QueueStorm Investigator is a small FastAPI service for the Codex Community Hackathon preliminary round. It exposes `GET /health` and `POST /analyze-ticket`, reads both the complaint and recent transaction history, and returns a structured support-agent decision with safe customer-facing text.

## Approach

The first version is rule-based and deterministic. That keeps latency low, makes the output reproducible, and avoids depending on external model calls during the judge run. The service:

- matches the complaint against transaction history to infer the most relevant transaction
- classifies the case into the exact taxonomy required by the problem statement
- supports **English, Banglish (romanized Bangla), and Bangla (Unicode)** complaint text
- assigns department, severity, and human-review flags
- generates safe agent and customer responses
- refuses unsafe prompt-injection and credential-request patterns

## API

### `GET /health`

Returns:

- `200 OK`
- `{"status":"ok"}`

### `POST /analyze-ticket`

Accepts the JSON request described in the problem statement and returns the required response shape.

Supported response fields:

- `ticket_id`
- `relevant_transaction_id`
- `evidence_verdict`
- `case_type`
- `severity`
- `department`
- `agent_summary`
- `recommended_next_action`
- `customer_reply`
- `human_review_required`
- `confidence`
- `reason_codes`

## Safety Logic

The service is designed to avoid unsafe fintech replies.

- It never asks for PIN, OTP, password, or full card number.
- It never confirms refunds, reversals, account unblocks, or recovery without authority.
- It directs users to official support channels only.
- It treats prompt-injection style text as suspicious and escalates it.

## Models

No external model is used in the current implementation.

- Model: none
- Runtime: local deterministic rules only
- Reason: no API key dependency, predictable latency, easier judge reproducibility

## Run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

## Deployment (Render)

The repository ships with `render.yaml` for one-click Render deployment.

1. Push the repository to GitHub.
2. In Render, choose **New +** → **Blueprint**, point it at the repo.
3. Render will detect `render.yaml`, build the `Dockerfile`, and deploy as a free web service.
4. Once live, the service URL responds to:
   - `GET /health` → `{"status":"ok"}`
   - `POST /analyze-ticket` with the JSON body documented above.

The `Dockerfile` uses `python:3.12-slim` and binds `uvicorn` to `$PORT` (Render sets it to `10000` by default; we override the CMD to honour it).

## Docker

```bash
docker build -t queuestorm-investigator .
docker run --rm -p 8000:8000 queuestorm-investigator
```

## Validation

Example health check:

```bash
curl http://localhost:8000/health
```

Example ticket call:

```bash
curl -X POST http://localhost:8000/analyze-ticket \
  -H 'content-type: application/json' \
  -d '{"ticket_id":"TKT-001","complaint":"I sent 5000 taka to a wrong number around 2pm today.","language":"en","transaction_history":[{"transaction_id":"TXN-9101","timestamp":"2026-04-14T14:08:22Z","type":"transfer","amount":5000,"counterparty":"+8801719876543","status":"completed"}]}'
```

## Assumptions

- Hidden tests may include Bangla, Banglish, malformed payloads, and adversarial prompt-injection text.
- Ambiguous or risky cases should be escalated instead of overconfidently guessed.
- The judge will score the exact enum values, schema shape, and safety text.

## Limitations

- The service uses heuristics instead of a trained model.
- Transaction matching is best-effort based on complaint text and the provided history.
- If the problem set includes cases that require domain knowledge outside the provided taxonomy, they are routed to `other`.
