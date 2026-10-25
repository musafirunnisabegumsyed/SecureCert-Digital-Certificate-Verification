import pytest
from app import create_app

@pytest.fixture()
def app(tmp_path):
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "DATABASE": str(tmp_path / "test.sqlite3"),
        "KEY_DIR": str(tmp_path / "keys"),
        "WTF_CSRF_ENABLED": False,
    })
    yield app

@pytest.fixture()
def client(app):
    return app.test_client()

@pytest.fixture()
def admin_client(client):
    response = client.post("/login", data={
        "username": "admin", "password": "ChangeMeNow!123"
    }, follow_redirects=True)
    assert response.status_code == 200
    return client
