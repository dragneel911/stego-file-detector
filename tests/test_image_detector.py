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


def test_jpeg_with_embedded_thumbnail_marker_uses_last_eoi_not_first():
    # A JPEG containing a complete nested JPEG (e.g. an EXIF thumbnail) has
    # its own end-of-image marker (FFD9) well before the real end of the
    # outer file. The appended-data check must anchor on the LAST FFD9
    # (rfind), not the first (find), or it will misreport the thumbnail's
    # end as the real end and wildly overcount "appended" bytes.
    inner_jpeg = _make_jpeg_bytes()
    outer_jpeg = _make_jpeg_bytes(size=(4, 4))
    junk = b"junkdata12345"
    data = inner_jpeg + outer_jpeg + junk

    is_suspicious, findings = scan_image(data)

    assert is_suspicious is True
    appended_findings = [f for f in findings if "appended" in f.lower()]
    assert len(appended_findings) == 1
    # The reported byte count must match the junk appended after the LAST
    # (real) end-of-image marker, not the count you'd get by anchoring on
    # the first FFD9 found inside `inner_jpeg`.
    assert str(len(junk)) in appended_findings[0]
    wrong_find_based_count = len(data) - (data.find(b"\xff\xd9") + 2)
    assert str(wrong_find_based_count) not in appended_findings[0]


def test_clean_jpeg_with_no_nested_marker_stays_clean():
    # A plain, real-shaped JPEG (no nested/embedded end-of-image marker)
    # must remain clean after switching from find() to rfind().
    is_suspicious, findings = scan_image(_make_jpeg_bytes())
    assert is_suspicious is False
    assert findings == []
