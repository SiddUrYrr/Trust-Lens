from pathlib import Path
from typing import Literal

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .analyzer import MAX_MESSAGE_LENGTH, analyze_message
from .ml_model import sms_ml_signal

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")  # loads GEMINI_API_KEY if present; safe if file absent
app = FastAPI(title="TrustLens", version="1.0.0", docs_url=None, redoc_url=None)



class AnalysisRequest(BaseModel):
    message: str = Field(min_length=1, max_length=MAX_MESSAGE_LENGTH)
    context: Literal["payment", "job", "phishing", "account", "general"] = "general"


@app.post("/api/analyze")
def analyze(request: AnalysisRequest):
    try:
        return analyze_message(request.message, request.context)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


from .ai_explainer import _get_model


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "mode": "local hybrid analysis",
        "sms_model_available": sms_ml_signal("health check")["available"],
        "ai_explainer_configured": _get_model() is not None,
    }


@app.get("/")
def index():
    return FileResponse(ROOT / "web" / "index.html")


app.mount("/assets", StaticFiles(directory=ROOT / "web"), name="assets")
