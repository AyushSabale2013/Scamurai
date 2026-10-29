import logging
import socket

import pytest
from fastapi.testclient import TestClient

from app.core import config

URL = "https://www.example.com"
PHISHY = "http://secure-login123.xyz/abcdefgh/ijklm.php?id=777"


def err(resp):
    body = resp.json()
    assert set(body) == {"error"} and {"code", "message"} <= set(body["error"])
    return body["error"]


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["status"] == "ok" and r.json()["model_loaded"] is True and r.json()["model_version"]


def test_model_info(client):
    r = client.get("/api/model-info")
    assert r.status_code == 200
    j = r.json()
    assert j["feature_count"] == len(j["feature_names"]) and j["class_mapping"] == {"0": "phishing", "1": "legitimate"}
    assert j["dataset"]["license"] == "CC BY 4.0" and j["headline_metrics"]["phishing_recall"] is not None


def test_predict_valid_schema(client):
    r = client.post("/api/predict", json={"url": PHISHY})
    assert r.status_code == 200
    j = r.json()
    assert j["predicted_class"] in (0, 1) and j["class_name"] in ("phishing", "legitimate")
    assert j["label"] in ("Potential phishing URL", "Likely legitimate URL")
    assert 0 <= j["phishing_score"] <= 1 and 0 < j["threshold"] < 1 and j["model_version"]
    assert (j["class_name"] == "phishing") == (j["phishing_score"] >= j["threshold"])
    assert len(j["features"]) == len(client.get("/api/model-info").json()["feature_names"])
    assert j["url_parts"]["registered_domain"] == "secure-login123.xyz" and "not guarantees" in j["disclaimer"]
    assert j["explanation"] and all(e["direction"] in ("toward_phishing", "toward_legitimate") for e in j["explanation"])


def test_predict_ranks_phishy_above_clean(client):
    a = client.post("/api/predict", json={"url": URL, "explain": False}).json()
    b = client.post("/api/predict", json={"url": PHISHY, "explain": False}).json()
    assert a["explanation"] is None and b["phishing_score"] > a["phishing_score"]
    assert a["class_name"] == "legitimate" and b["class_name"] == "phishing"


def test_scheme_less_input_flagged(client):
    j = client.post("/api/predict", json={"url": "example.com/x"}).json()
    assert j["url_parts"]["scheme_assumed"] is True and j["notes"]


@pytest.mark.parametrize("payload", [{}, {"url": ""}, {"url": 5}, {"url": None}])
def test_predict_validation_errors_are_consistent(client, payload):
    r = client.post("/api/predict", json=payload)
    assert r.status_code == 422 and err(r)["code"] == "validation_error"


def test_predict_unanalysable_url(client):
    for bad in ("ftp://example.com", "http://", "not a url", "http://a..b"):
        r = client.post("/api/predict", json={"url": bad})
        assert r.status_code == 422 and err(r)["code"] == "invalid_url"


def test_oversized_inputs(client):
    r = client.post("/api/predict", json={"url": "https://e.com/" + "a" * 3000})
    assert r.status_code == 422 and err(r)["code"] == "invalid_url"          # over extractor limit
    r = client.post("/api/predict", json={"url": "a" * 5000})
    assert r.status_code == 422 and err(r)["code"] == "validation_error"     # over schema limit
    r = client.post("/api/predict", content=b"x" * 2_000_000, headers={"content-type": "application/json"})
    assert r.status_code == 413 and err(r)["code"] == "payload_too_large"


def test_batch_mixed_results(client):
    urls = [URL, "ftp://nope.com", PHISHY, "", "http://a..b"]
    r = client.post("/api/predict/batch", json={"urls": urls})
    assert r.status_code == 200
    j = r.json()
    assert j["total"] == 5 and j["ok"] == 2 and j["invalid"] == 3
    assert [x["index"] for x in j["results"]] == [0, 1, 2, 3, 4]
    assert j["results"][1]["status"] == "invalid" and j["results"][1]["error"]["code"] == "unsupported_scheme"
    assert j["results"][0]["class_name"] == "legitimate" and j["results"][2]["class_name"] == "phishing"
    assert all("url" not in x for x in j["results"])


def test_batch_limits(client, monkeypatch):
    big = {"urls": [URL] * 101}
    r = client.post("/api/predict/batch", json=big)
    assert r.status_code == 413 and err(r)["code"] == "batch_too_large"
    assert client.post("/api/predict/batch", json={"urls": []}).status_code == 422


def test_analytics_and_metrics_come_from_saved_report(client, trained_dir):
    s = client.get("/api/analytics/summary").json()
    assert s["dataset"]["raw_rows"] > 0 and s["headline"]["phishing_recall"] > 0 and len(s["models"]) == 6
    m = client.get("/api/model-metrics").json()
    assert "experiments" in m and "shortcut_diagnostics" in m


def test_missing_model_gives_clean_errors(tmp_path, monkeypatch):
    monkeypatch.setenv("PHISHGUARD_ARTIFACT_DIR", str(tmp_path))
    config.get_settings.cache_clear()
    from app.main import create_app

    with TestClient(create_app()) as c:
        h = c.get("/api/health").json()
        assert h["status"] == "degraded" and h["model_loaded"] is False
        r = c.post("/api/predict", json={"url": URL})
        assert r.status_code == 503 and err(r)["code"] == "model_unavailable"
        assert c.get("/api/model-info").status_code == 503
        r = c.get("/api/analytics/summary")
        assert r.status_code == 503 and err(r)["code"] == "report_unavailable"
    config.get_settings.cache_clear()


def test_unknown_route_uses_error_envelope(client):
    r = client.get("/api/nope")
    assert r.status_code == 404 and err(r)["code"] == "not_found"


def test_no_outbound_network_during_prediction(client, monkeypatch):
    calls = []

    def blocked(*a, **k):
        calls.append(a)
        raise AssertionError("outbound network attempted")

    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    assert client.post("/api/predict", json={"url": "http://definitely-not-real-host-12345.invalid/login"}).status_code == 200
    assert client.post("/api/predict/batch", json={"urls": ["https://a.example/x", "http://b.example/y"]}).status_code == 200
    assert not calls


def test_submitted_urls_never_logged(client, caplog):
    secret = "https://www.secret-token-abc123.example/path?password=hunter2"
    with caplog.at_level(logging.DEBUG):
        client.post("/api/predict", json={"url": secret})
        client.post("/api/predict/batch", json={"urls": [secret]})
    text = " ".join(r.getMessage() + str(getattr(r, "fields", "")) for r in caplog.records)
    assert "hunter2" not in text and "secret-token" not in text
