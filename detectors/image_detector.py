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
