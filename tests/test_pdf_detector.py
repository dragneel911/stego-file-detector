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


def _make_password_protected_pdf_bytes():
    pdf = pikepdf.Pdf.new()
    pdf.add_blank_page()
    buf = io.BytesIO()
    pdf.save(buf, encryption=pikepdf.Encryption(owner="ownerpw", user="userpw"))
    return buf.getvalue()


def test_password_protected_pdf_is_flagged_not_raised():
    is_suspicious, findings = scan_pdf(_make_password_protected_pdf_bytes())
    assert is_suspicious is True
    assert any("password" in f.lower() for f in findings)
