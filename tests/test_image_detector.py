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
