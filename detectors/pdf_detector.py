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
