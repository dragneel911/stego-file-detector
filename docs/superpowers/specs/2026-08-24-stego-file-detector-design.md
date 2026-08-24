# Steganography & Suspicious File Detector — Design

## Purpose

A small, resume-friendly web tool that lets a user upload a file
(image, PDF, or `.bat`) and get back a plain-language verdict on
whether it shows signs of hidden data or malicious intent. Built by a
fresher, for a fresher's resume: every check must be simple enough to
explain confidently in an interview — no deep statistical or
cryptographic techniques, no unnecessary infrastructure (no database,
no accounts, no history).

## Success criteria

- Upload a `.png`/`.jpg`, a `.pdf`, or a `.bat` file through a web
  page and get a clear result: a verdict plus the specific reasons
  behind it.
- Each detector's logic is simple enough to describe in 1-2 sentences.
- Runs locally with a single `python app.py` (or `flask run`), no
  external services.
- Has unit tests proving each detector correctly flags rigged sample
  files and passes clean ones.

## Non-goals

- No payload extraction/decoding — detection only.
- No statistical/LSB analysis, chi-square tests, or other stego math.
- No scan history, database, or user accounts.
- No support for file types beyond images (`.png`/`.jpg`), `.pdf`,
  and `.bat`.
- No deployment/hosting setup — local run only (can be added later).

## Architecture

A single Flask app with one page: an upload form and a results
display. The flow is stateless — one request in, one rendered result
out. The extension of the uploaded file decides which detector module
runs.

```
stego-detector/
├── app.py                 # Flask routes: "/" (GET form, POST upload+result)
├── detectors/
│   ├── image_detector.py  # heuristic checks for images
│   ├── pdf_detector.py    # suspicious PDF object checks
│   └── bat_detector.py    # keyword/pattern checks for .bat lines
├── templates/
│   └── index.html         # upload form + results display (same page)
├── static/
│   └── style.css          # minimal styling
├── tests/
│   ├── fixtures/           # clean + rigged sample files per type
│   ├── test_image_detector.py
│   ├── test_pdf_detector.py
│   └── test_bat_detector.py
└── requirements.txt        # Flask, pikepdf (or PyPDF2), Pillow, pytest
```

## Components

### `app.py`
- `GET /` — renders the upload form.
- `POST /` — receives the uploaded file, validates extension and size,
  dispatches to the matching detector, renders the result on the same
  template.
- Owns error handling for unsupported types, oversized files, and
  detector-level failures (corrupted/unparsable files).

### `detectors/image_detector.py`
Input: image file bytes. Output: `(is_suspicious: bool, findings: list[str])`.

Checks:
- Appended data after the image's real end-of-data marker (e.g. bytes
  found after PNG's `IEND` chunk, or after JPEG's `FFD9` end marker).
- Gross size-vs-dimensions mismatch that doesn't fit a normal image
  for that format.

### `detectors/pdf_detector.py`
Input: PDF file bytes. Output: `(is_suspicious: bool, findings: list[str])`.

Checks, via `pikepdf`:
- Object dictionary contains any of: `/JavaScript`, `/JS`,
  `/EmbeddedFile`, `/Launch`.
- Bytes appended after the file's final `%%EOF` marker.

### `detectors/bat_detector.py`
Input: `.bat` file text. Output: `(is_suspicious: bool, findings: list[str])`
where each finding includes the line number, matched keyword, and a
short reason.

Fixed pattern list (case-insensitive substring match), grouped by
intent:
- **Download/fetch**: `certutil`, `bitsadmin`, `powershell -enc`,
  `curl`, `wget`
- **Security tampering**: `netsh firewall`, `sc stop`
- **Obfuscation**: `base64`
- **Persistence**: `reg add ... Run`, `schtasks`

### `templates/index.html`
Upload form (file input + submit) and, after a POST, a result block:
overall verdict line ("No suspicious indicators found" / "N suspicious
indicators found") followed by a bullet list of findings with their
reasons.

## Data flow

1. User selects a file and submits the form.
2. `app.py` validates: extension is one of the three supported types,
   size is under the limit (10MB).
3. `app.py` reads file bytes/text and calls the matching detector
   function.
4. Detector returns `(is_suspicious, findings)`.
5. `app.py` renders `index.html` with the verdict and findings.

## Error handling

- Unsupported extension → render the form again with a plain error
  message, no crash.
- File over 10MB → same, rejected before any detector runs.
- Detector raises on a corrupted/unparsable file → caught in `app.py`,
  shown as "This file couldn't be analyzed" rather than a stack trace
  or 500 error.

## Testing

`pytest` unit tests per detector module, using hand-crafted fixture
files in `tests/fixtures/`:
- One clean and one rigged sample per file type (e.g. a plain PNG vs.
  one with bytes appended after `IEND`; a plain PDF vs. one with
  `/JavaScript`; a benign `.bat` vs. one with a `certutil` download
  line).
- Each test asserts the detector's `is_suspicious` flag and that the
  expected finding text/line number appears in `findings`.
- No UI/integration tests — form submission is simple enough to be
  covered by manual verification during development.

## Naming

Working directory name during development stays `CYBER-PROject`
(current repo). Once the project is complete and verified, the folder
will be renamed to something reflecting the final tool, e.g.
`stego-file-detector` — done as an explicit last step per the user's
request, after implementation and testing are done.
