from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse

from .investigator import decide_case
from .schemas import AnalyzeTicketRequest, AnalyzeTicketResponse

app = FastAPI(title="QueueStorm Investigator", version="0.1.0")


@app.get("/")
def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/analyze-ticket")
async def analyze_ticket(ticket: AnalyzeTicketRequest) -> AnalyzeTicketResponse:
    try:
        result = decide_case(ticket)
    except Exception:
        raise HTTPException(status_code=500, detail="Internal analysis error") from None

    return result
