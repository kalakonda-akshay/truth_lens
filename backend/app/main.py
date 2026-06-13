from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

from app.config import get_settings
from app.database import init_db
from app.models import AnalysisReport
from app.services.analyzer import analyze_upload
from app.services.pdf import build_pdf
from app.services.storage import get_report, save_report

settings = get_settings()
app = FastAPI(title=settings.app_name, version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/frames", StaticFiles(directory=settings.storage_dir / "frames"), name="frames")


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "truthlens-api"}


@app.post("/analyze", response_model=AnalysisReport)
async def analyze(file: UploadFile = File(...)) -> AnalysisReport:
    if not file.filename:
        raise HTTPException(status_code=400, detail="A media file is required.")
    report = analyze_upload(file.filename, file.content_type, file.file)
    save_report(report)
    return report


@app.get("/reports/{report_id}", response_model=AnalysisReport)
def report(report_id: str) -> AnalysisReport:
    stored = get_report(report_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    return stored


@app.get("/reports/{report_id}/pdf")
def pdf(report_id: str) -> Response:
    stored = get_report(report_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    return Response(
        build_pdf(stored),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="truthlens-{report_id}.pdf"'},
    )
