from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.openapi.utils import get_openapi

from .investigator import decide_case
from .schemas import AnalyzeTicketRequest, AnalyzeTicketResponse

# Custom Swagger UI tweaks. These are passed straight through to swagger-ui's
# bootstrap configuration by FastAPI — see Swagger UI parameter docs.
SWAGGER_UI_PARAMETERS: dict = {
    # Tame default expansion so the page isn't 2000 lines tall on first load.
    "docExpansion": "list",
    "defaultModelsExpandDepth": -1,   # collapse schemas by default
    "defaultModelExpandDepth": 3,
    "deepLinking": True,
    "displayOperationId": False,
    "filter": True,                   # add the search/filter bar at the top
    "tryItOutEnabled": True,          # open the "Try it out" panel by default
    "syntaxHighlight": {"activated": True, "theme": "nord"},
    # The visual refinements live in this stylesheet, served from /static.
    "customCssUrl": "/static/swagger.css",
}

app = FastAPI(
    title="QueueStorm Investigator",
    version="0.1.0",
    swagger_ui_parameters=SWAGGER_UI_PARAMETERS,
)

# Serve project-local static files (currently just swagger.css) at /static.
STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


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

    post_operation = openapi_schema.get("paths", {}).get("/analyze-ticket", {}).get("post")
    if post_operation and "responses" in post_operation:
        post_operation["responses"].pop("422", None)

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi
