from fastapi import FastAPI, UploadFile, File, Request, Body
from fastapi.responses import (
    HTMLResponse,
    Response,
    RedirectResponse,
    JSONResponse
)
from fastapi.templating import Jinja2Templates
import shutil
import tempfile
import os

from main import run_analysis
from copilot import (
    generate_copilot_insights,
    generate_llm_analysis,
    generate_chat_response
)
from storage import save_results, load_results, load_pdf

app = FastAPI()
templates = Jinja2Templates(directory="templates")


# =========================
# LANDING PAGE
# =========================
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse(
        request,
        "index.html",
        {}
    )


# =========================
# UPLOAD PAGE
# =========================
@app.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request):
    return templates.TemplateResponse(
        request,
        "upload.html",
        {}
    )


# =========================
# ANALYZE FIRMWARE
# =========================
@app.post("/analyze", response_class=HTMLResponse)
async def analyze_firmware(
    request: Request,
    original_file: UploadFile = File(...),
    modified_file: UploadFile = File(...)
):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as temp_original:
        shutil.copyfileobj(original_file.file, temp_original)
        original_path = temp_original.name

    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as temp_modified:
        shutil.copyfileobj(modified_file.file, temp_modified)
        modified_path = temp_modified.name

    try:
        results = run_analysis(original_path, modified_path)

        # ✅ persist analysis to disk
        save_results(results)

    finally:
        if os.path.exists(original_path):
            os.remove(original_path)
        if os.path.exists(modified_path):
            os.remove(modified_path)

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"results": results}
    )


# =========================
# REPORT PAGE
# =========================
@app.get("/report", response_class=HTMLResponse)
async def report(request: Request):
    results = load_results()

    if not results:
        return RedirectResponse("/upload")

    return templates.TemplateResponse(
        request,
        "report.html",
        {"results": results}
    )


# =========================
# COPILOT PAGE
# =========================
@app.get("/copilot", response_class=HTMLResponse)
async def copilot(request: Request):
    results = load_results()

    if not results:
        return RedirectResponse("/upload")

    insights = generate_copilot_insights(results)
    llm_analysis = generate_llm_analysis(results)

    return templates.TemplateResponse(
        request,
        "copilot.html",
        {
            "results": results,
            "insights": insights,
            "llm_analysis": llm_analysis
        }
    )


# =========================
# LIVE CHAT ENDPOINT
# =========================
@app.post("/copilot/chat")
async def copilot_chat(payload: dict = Body(...)):
    results = load_results()

    if not results:
        return JSONResponse({
            "reply": "No firmware analysis is loaded yet. Please upload firmware first."
        })

    user_message = payload.get("message", "").strip()

    if not user_message:
        return JSONResponse({
            "reply": "Please enter a valid question."
        })

    reply = generate_chat_response(results, user_message)

    return JSONResponse({"reply": reply})


# =========================
# PDF EXPORT
# =========================
@app.get("/download-report")
async def download_report():
    pdf_bytes = load_pdf()

    if not pdf_bytes:
        return Response(
            content=b"No report available",
            media_type="text/plain"
        )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition":
            "attachment; filename=firmware_forensics_report.pdf"
        }
    )
# =========================
# JSON EXPORT
# =========================
@app.get("/download-json")
async def download_json():
    results = load_results()

    if not results:
        return JSONResponse({"error": "No report available"})

    return JSONResponse(results)


# =========================
# ABOUT PAGE
# =========================
@app.get("/about", response_class=HTMLResponse)
async def about(request: Request):
    return templates.TemplateResponse(
        request,
        "about.html",
        {}
    )