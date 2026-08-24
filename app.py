import os

from flask import Flask, render_template, request

from detectors.bat_detector import scan_bat
from detectors.image_detector import scan_image
from detectors.pdf_detector import scan_pdf

app = Flask(__name__)

MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

EXTENSION_MAP = {
    ".png": ("image", scan_image),
    ".jpg": ("image", scan_image),
    ".jpeg": ("image", scan_image),
    ".pdf": ("pdf", scan_pdf),
    ".bat": ("bat", scan_bat),
}


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None

    if request.method == "POST":
        uploaded = request.files.get("file")
        if uploaded is None or uploaded.filename == "":
            error = "Please choose a file to upload."
        else:
            filename = uploaded.filename
            ext = os.path.splitext(filename)[1].lower()
            if ext not in EXTENSION_MAP:
                error = (
                    f"Unsupported file type '{ext}'. "
                    "Supported: .png, .jpg, .jpeg, .pdf, .bat"
                )
            else:
                file_bytes = uploaded.read()
                if len(file_bytes) > MAX_FILE_SIZE:
                    error = "File is too large (max 10MB)."
                else:
                    kind, scan_fn = EXTENSION_MAP[ext]
                    try:
                        if kind == "bat":
                            is_suspicious, findings = scan_fn(
                                file_bytes.decode("utf-8", errors="replace")
                            )
                        else:
                            is_suspicious, findings = scan_fn(file_bytes)
                        result = {
                            "filename": filename,
                            "is_suspicious": is_suspicious,
                            "findings": findings,
                        }
                    except Exception:
                        error = "This file couldn't be analyzed."

    return render_template("index.html", result=result, error=error)


if __name__ == "__main__":
    app.run(debug=True)
