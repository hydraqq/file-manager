import requests

BASE_URL = "http://localhost:8000"


def login(session: requests.Session, username: str, password: str) -> None:
    r = session.post(f"{BASE_URL}/login", json={"username": username, "password": password})
    assert r.status_code == 200, f"Login failed for {username}: {r.text}"


def test_idor_protection() -> None:
    alice = requests.Session()
    login(alice, "alice", "Alice123!")
    r = alice.get(f"{BASE_URL}/files/2")
    assert r.status_code == 404, f"IDOR vulnerability! Status: {r.status_code}, body: {r.text}"
    print("Test 1 PASSED: IDOR protection works")


def test_own_file_access() -> None:
    alice = requests.Session()
    login(alice, "alice", "Alice123!")
    r = alice.get(f"{BASE_URL}/files/1")
    assert r.status_code == 200, f"Cannot access own file: {r.status_code}"
    print("Test 2 PASSED: Own file access works")


def test_admin_delete() -> None:
    admin = requests.Session()
    login(admin, "admin", "Admin123!")
    r = admin.delete(f"{BASE_URL}/files/2")
    assert r.status_code == 200, f"Admin delete failed: {r.status_code}"
    print("Test 3 PASSED: Admin can delete any file")


if __name__ == "__main__":
    test_idor_protection()
    test_own_file_access()
    test_admin_delete()
    print("\nAll security tests passed!")
