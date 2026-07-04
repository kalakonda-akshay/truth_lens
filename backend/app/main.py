from fastapi import FastAPI, File, Header, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import requests

from app.config import get_settings
from app.database import init_db
from app.models import AnalysisReport
from app.services.analyzer import analyze_email_text, analyze_upload, analyze_url_text
from app.services.pdf import build_pdf
from app.services.integrity import attach_integrity, verification_record
from app.services.auth import (
    authenticate_token,
    admin_reset_user_password,
    change_password,
    ensure_founder_admin,
    google_login,
    login_user,
    logout_user,
    register_user,
    request_login_otp,
    verify_login_otp,
)
from app.services.storage import get_report, list_admin_analyses, list_admin_users, list_reports, save_report

settings = get_settings()
app = FastAPI(title=settings.app_name, version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins or ["*"],
    allow_origin_regex=settings.origin_regex,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/frames", StaticFiles(directory=settings.storage_dir / "frames"), name="frames")


class TextAnalysisRequest(BaseModel):
    content: str


class CredentialsRequest(BaseModel):
    email: str
    password: str
    name: str = ""


class GoogleRequest(BaseModel):
    credential: str


class ForgotPasswordRequest(BaseModel):
    email: str


class OtpVerifyRequest(BaseModel):
    challenge_id: str
    code: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


def _bearer_token(authorization: str | None) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        return ""
    return authorization.split(" ", 1)[1].strip()


def _current_user(authorization: str | None, required: bool = True) -> dict[str, str] | None:
    user = authenticate_token(_bearer_token(authorization))
    if required and user is None:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


def _current_admin(authorization: str | None) -> dict[str, str]:
    user = _current_user(authorization)
    if user["role"] != "founder_admin":
        raise HTTPException(status_code=403, detail="Founder administrator access required.")
    return user


def _auth_response(action) -> dict:
    try:
        user, token = action()
        return {"user": user, "token": token}
    except (ValueError, requests.RequestException) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.on_event("startup")
def startup() -> None:
    init_db()
    ensure_founder_admin()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "truthlens-api"}


@app.post("/auth/signup")
def signup(request: CredentialsRequest) -> dict:
    return _auth_response(lambda: register_user(request.name, request.email, request.password))


@app.post("/auth/login")
def login(request: CredentialsRequest) -> dict:
    return _auth_response(lambda: login_user(request.email, request.password))


@app.post("/auth/login/request")
def login_request(request: CredentialsRequest) -> dict:
    try:
        return request_login_otp(request.email, request.password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/auth/login/verify")
def login_verify(request: OtpVerifyRequest) -> dict:
    return _auth_response(lambda: verify_login_otp(request.challenge_id, request.code))


@app.post("/auth/google")
def login_google(request: GoogleRequest) -> dict:
    return _auth_response(lambda: google_login(request.credential))


@app.post("/auth/forgot-password")
def forgot_password(request: ForgotPasswordRequest) -> dict[str, str]:
    return {
        "status": "accepted",
        "message": "If an account exists, password recovery instructions will be sent by the configured identity provider.",
    }


@app.post("/auth/change-password")
def update_password(request: ChangePasswordRequest, authorization: str | None = Header(None)) -> dict:
    user = _current_user(authorization)
    try:
        updated_user = change_password(user["id"], request.current_password, request.new_password)
        return {"user": updated_user, "message": "Password updated. Please log in again."}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/auth/me")
def me(authorization: str | None = Header(None)) -> dict[str, str]:
    return _current_user(authorization)


@app.post("/auth/logout")
def logout(authorization: str | None = Header(None)) -> dict[str, str]:
    token = _bearer_token(authorization)
    if token:
        logout_user(token)
    return {"status": "signed_out"}


@app.post("/analyze", response_model=AnalysisReport)
async def analyze(file: UploadFile = File(...), authorization: str | None = Header(None)) -> AnalysisReport:
    if not file.filename:
        raise HTTPException(status_code=400, detail="A media file is required.")
    report = analyze_upload(file.filename, file.content_type, file.file)
    report = attach_integrity(report)
    user = _current_user(authorization, required=False)
    save_report(report, user["id"] if user else None)
    return report


@app.post("/analyze/url", response_model=AnalysisReport)
async def analyze_url(request: TextAnalysisRequest, authorization: str | None = Header(None)) -> AnalysisReport:
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="A URL is required.")
    report = analyze_url_text(request.content.strip())
    report = attach_integrity(report)
    user = _current_user(authorization, required=False)
    save_report(report, user["id"] if user else None)
    return report


@app.post("/analyze/email", response_model=AnalysisReport)
async def analyze_email(request: TextAnalysisRequest, authorization: str | None = Header(None)) -> AnalysisReport:
    if not request.content.strip():
        raise HTTPException(status_code=400, detail="Email content is required.")
    report = analyze_email_text(request.content)
    report = attach_integrity(report)
    user = _current_user(authorization, required=False)
    save_report(report, user["id"] if user else None)
    return report


@app.get("/user/reports", response_model=list[AnalysisReport])
def user_reports(authorization: str | None = Header(None)) -> list[AnalysisReport]:
    user = _current_user(authorization)
    return list_reports(user["id"])


@app.get("/admin/users")
def admin_users(authorization: str | None = Header(None)) -> dict:
    _current_admin(authorization)
    return {"users": list_admin_users()}


@app.post("/admin/users/{user_id}/reset-password")
def admin_reset_password(user_id: str, authorization: str | None = Header(None)) -> dict:
    _current_admin(authorization)
    try:
        return admin_reset_user_password(user_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.get("/admin/analyses")
def admin_analyses(authorization: str | None = Header(None)) -> dict:
    _current_admin(authorization)
    analyses = list_admin_analyses()
    return {"analyses": analyses}


@app.get("/admin/summary")
def admin_summary(authorization: str | None = Header(None)) -> dict:
    _current_admin(authorization)
    users = list_admin_users()
    analyses = list_admin_analyses()
    high_risk_levels = {"high", "critical", "malicious"}
    image_reports = [item for item in analyses if item["media_type"] == "image"]
    return {
        "total_users": len(users),
        "total_analyses": len(analyses),
        "image_uploads": len(image_reports),
        "high_risk_reports": sum(1 for item in analyses if str(item["risk_level"]).lower() in high_risk_levels),
        "latest_image_reports": image_reports[:20],
    }


@app.get("/reports/{report_id}", response_model=AnalysisReport)
def report(report_id: str) -> AnalysisReport:
    stored = get_report(report_id)
    if stored is None:
        raise HTTPException(status_code=404, detail="Report not found.")
    return stored


@app.get("/reports/{report_id}/verify")
def verify_report(report_id: str) -> dict:
    return verification_record(get_report(report_id))


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
