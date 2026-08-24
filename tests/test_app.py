from app import app


def test_index_get_shows_upload_form():
    client = app.test_client()
    response = client.get("/")
    assert response.status_code == 200
    assert b'type="file"' in response.data
