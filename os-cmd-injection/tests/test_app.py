"""
Basic tests proving the vulnerability exists on /vulnerable and is blocked
on /secure. Run with: pytest -v
Having tests like this in your repo is good practice on its own, and it's
also a quick way to re-confirm both routes behave as expected before you
record your demo.
"""

import app as flaskapp


def client():
    return flaskapp.app.test_client()


def test_home_loads():
    c = client()
    r = c.get("/")
    assert r.status_code == 200


def test_health_check():
    c = client()
    r = c.get("/health")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_vulnerable_route_executes_injected_command():
    c = client()
    r = c.post("/vulnerable", data={"host": "127.0.0.1; echo INJECTED_MARKER"})
    assert "INJECTED_MARKER" in r.get_data(as_text=True)


def test_secure_route_blocks_same_payload():
    c = client()
    r = c.post("/secure", data={"host": "127.0.0.1; echo INJECTED_MARKER"})
    body = r.get_data(as_text=True)
    # The rejected host text is still shown back to the user (that's fine —
    # it's just displaying what was typed, not executing it), so the right
    # check is that no command actually ran: no "Output:" section appears,
    # and the rejection message is present.
    assert "Invalid host" in body
    assert "<h3>Output:</h3>" not in body


def test_secure_route_allows_legitimate_host():
    c = client()
    r = c.post("/secure", data={"host": "127.0.0.1"})
    assert "Invalid host" not in r.get_data(as_text=True)
