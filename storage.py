import json
from pathlib import Path

RESULT_PATH = Path("samples/latest_results.json")
PDF_PATH = Path("samples/latest_report.pdf")


def save_results(results):
    exportable = {
        k: v for k, v in results.items()
        if k not in ["pdf_report"]
    }

    RESULT_PATH.parent.mkdir(parents=True, exist_ok=True)

    with open(RESULT_PATH, "w") as f:
        json.dump(exportable, f, indent=4)

    # save pdf bytes separately
    pdf_bytes = results.get("pdf_report")
    if pdf_bytes:
        with open(PDF_PATH, "wb") as f:
            f.write(pdf_bytes)


def load_results():
    if not RESULT_PATH.exists():
        return None

    with open(RESULT_PATH, "r") as f:
        return json.load(f)


def load_pdf():
    if not PDF_PATH.exists():
        return None

    with open(PDF_PATH, "rb") as f:
        return f.read()