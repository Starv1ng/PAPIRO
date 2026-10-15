from fastapi.testclient import TestClient

from app.main import app


def test_ui_landing_is_only_for_login_and_registration():
    with TestClient(app) as client:
        response = client.get("/ui")
        assert response.status_code == 200
        assert "loginForm" in response.text
        assert '<html lang="en-US">' in response.text
        assert "<title>PAPIRO · Sign in</title>" in response.text
        assert 'property="og:title" content="PAPIRO"' in response.text
        assert "Kami-no-Eye" not in response.text
        assert "registerForm" in response.text
        assert "/auth/register" in response.text
        assert "location.replace('/ui/workspace')" in response.text
        assert 'id="investigationList"' not in response.text


def test_workspace_has_own_dashboard_and_optional_investigation_creation():
    with TestClient(app) as client:
        response = client.get("/ui/workspace")
        assert response.status_code == 200
        assert 'id="investigationList"' in response.text
        assert 'id="totalInvestigations"' in response.text
        assert 'id="newInvestigationButton"' in response.text
        assert 'id="investigationForm" hidden' in response.text
        assert "it is not required to access your workspace" in response.text
        assert 'id="logoutModal"' in response.text
        assert 'id="investigationName"' in response.text
        assert 'id="investigationNotes"' in response.text
        assert "request('/investigations'" in response.text
        assert "request('/ingest/name'" not in response.text


def test_investigation_ui_has_autosave_exit_and_logout_confirmation():
    with TestClient(app) as client:
        response = client.get("/ui/job/example-job")
        assert response.status_code == 200
        assert "PAPIRO · Investigation workspace" in response.text
        assert 'id="saveStatus"' in response.text
        assert 'id="saveExitBtn"' in response.text
        assert 'id="sessionModal"' in response.text
        assert 'id="saveAndLogout"' in response.text
        assert 'id="logoutWithoutViewSave"' in response.text
        assert 'id="cancelSessionExit"' in response.text
        assert 'id="leaveWithoutSaving"' in response.text
        assert 'id="saveAndLeave"' in response.text
        assert "DOMContentLoaded" in response.text
        assert "View saved automatically" in response.text
        assert "/checkpoint" in response.text
        assert "/checkpoint/restore" in response.text
        assert "/checkpoint/commit" in response.text
        assert "reverts changes from this session" in response.text
        assert "rememberLocalBaseline" in response.text
