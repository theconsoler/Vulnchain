import pytest
import json
from app import create_app
from app.auth import hash_password, verify_password


@pytest.fixture
def client(tmp_path):
    app = create_app({
        "TESTING":          True,
        "DB_PATH":          str(tmp_path / "test.db"),
        "UPLOAD_FOLDER":    str(tmp_path / "uploads"),
        "OUTPUT_FOLDER":    str(tmp_path / "output"),
        "JWT_COOKIE_CSRF_PROTECT": False,
    })
    with app.test_client() as client:
        yield client


def test_login_page_loads(client):
    res = client.get("/login")
    assert res.status_code == 200
    assert b"VulnChain" in res.data

def test_login_wrong_password(client):
    res = client.post("/login",
        data=json.dumps({"username": "nobody", "password": "wrong"}),
        content_type="application/json")
    assert res.status_code == 401

def test_dashboard_requires_auth(client):
    res = client.get("/dashboard")
    assert res.status_code in [302, 401]

def test_hash_password_is_not_plaintext():
    hashed = hash_password("mypassword")
    assert hashed != "mypassword"
    assert hashed.startswith("$2b$")

def test_verify_password_correct():
    hashed = hash_password("testpass123")
    assert verify_password("testpass123", hashed) is True

def test_verify_password_wrong():
    hashed = hash_password("testpass123")
    assert verify_password("wrongpass", hashed) is False

def test_api_stats_requires_auth(client):
    res = client.get("/api/stats")
    assert res.status_code in [302, 401, 422]

def test_api_vulns_no_data(client):
    # Without auth this should redirect or 401
    res = client.get("/api/vulns")
    assert res.status_code in [302, 401, 422]
