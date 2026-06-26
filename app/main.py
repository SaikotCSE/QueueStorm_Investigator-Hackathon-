from __future__ import annotations

from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.openapi.utils import get_openapi

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


def custom_openapi() -> dict:
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        routes=app.routes,
    )

    analyze_ticket_path = openapi_schema.get("paths", {}).get("/analyze-ticket", {})
    post_operation = analyze_ticket_path.get("post")
    if post_operation and "responses" in post_operation:
        post_operation["responses"].pop("422", None)

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi
