from fastapi.testclient import TestClient

from app.main import app


def test_registration_offers_non_admin_roles_and_preserves_public_role():
    with TestClient(app) as client:
        response = client.get("/ui")
    assert response.status_code == 200
    assert 'id="registerRole"' in response.text
    assert 'value="investigator"' in response.text
    assert 'value="user"' in response.text
    assert 'value="superuser"' not in response.text


def test_investigation_workspace_exposes_share_and_merge_controls():
    with TestClient(app) as client:
        response = client.get("/ui/job/example")
    assert response.status_code == 200
    assert 'id="shareInvestigationBtn"' in response.text
    assert 'id="mergeInvestigationBtn"' in response.text
    assert 'id="sharePermission"' in response.text
    assert "/shares/" in response.text

def test_collaboration_and_deletion_routes_are_registered():
    from app.main import app

    routes = {
        (route.path, method)
        for route in app.routes
        for method in (getattr(route, "methods", None) or set())
    }
    assert ("/api/v1/jobs/{job_id}", "DELETE") in routes
    assert ("/api/v1/jobs/{job_id}/shares", "POST") in routes
    assert ("/api/v1/jobs/{job_id}/shares/{share_id}/merge", "POST") in routes
    assert ("/api/v1/shares/{share_id}/comments", "POST") in routes

def test_sharing_creates_an_independent_copy(monkeypatch):
    from contextlib import contextmanager
    from fastapi import FastAPI, Request
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app import api
    from app.db import Base
    from app.models import InvestigationShare, Job, JobStatus, User, UserRole

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    owner = User(email="owner@example.com", password_hash="test", global_role=UserRole.investigator)
    collaborator = User(email="collaborator@example.com", password_hash="test", global_role=UserRole.investigator)
    session.add_all([owner, collaborator])
    session.flush()
    original = Job(
        input_value="Example investigation",
        investigation_title="Example investigation",
        input_type="investigation",
        status=JobStatus.draft,
        owner_user_id=owner.id,
    )
    session.add(original)
    session.flush()
    original_id = original.id

    @contextmanager
    def fake_db_session():
        yield session

    def fake_auth(request: Request):
        request.state.current_user_id = owner.id

    monkeypatch.setattr(api, "db_session", fake_db_session)
    app = FastAPI()
    app.include_router(api.router)
    app.dependency_overrides[api.authorize_api_request] = fake_auth
    with TestClient(app) as client:
        response = client.post(
            f"/api/v1/jobs/{original_id}/shares",
            json={"email": "collaborator@example.com", "permission": "edit"},
        )
    assert response.status_code == 201, response.text
    share = session.scalar(select(InvestigationShare))
    assert share is not None
    assert share.original_job_id == original_id
    assert share.shared_job_id != original_id
    assert share.permission == "edit"
    copy = session.get(Job, share.shared_job_id)
    assert copy is not None
    assert copy.owner_user_id == collaborator.id
    assert session.get(Job, original_id).owner_user_id == owner.id

    session.close()
    engine.dispose()

def test_read_only_shared_copy_can_exit_without_checkpoint_or_restore():
    with TestClient(app) as client:
        response = client.get("/ui/job/example")
    assert response.status_code == 200
    html = response.text
    # A read-only copy must be detected before opening an editing checkpoint.
    assert "const isReadOnly=await window.detectReadOnlySession();" in html
    assert "if(!isReadOnly)await beginInvestigationEditingSession();" in html
    # Exit/logout must bypass server-side commit/restore for read-only sessions.
    assert "if(readOnlySession||!checkpointReady){restoreLocalBaseline();location.href='/ui/workspace';return;}" in html
    assert "if(readOnlySession||!checkpointReady){restoreLocalBaseline();localStorage.removeItem(TOKEN_KEY);location.replace('/ui');return;}" in html
    # Editing remains unavailable in the UI; server-side authorization remains authoritative.
    assert "activateReadOnlyMode" in html
    assert "if(job?.can_edit===false){activateReadOnlyMode();return true;}" in html
    assert "Read-only access" in html
    assert "assessFinding|assessRelationship|assessCorrelation|saveEntity|saveRelationship|openEntityEdit|openRelationshipEdit|attachSelectedFindingsToEntity" in html
    from pathlib import Path
    auth_source = (Path(__file__).resolve().parents[1] / "app" / "auth.py").read_text(encoding="utf-8")
    assert "This shared copy does not grant editing permission" in auth_source


def test_entity_organization_requires_administrative_provisioning(monkeypatch):
    from contextlib import contextmanager
    from fastapi import HTTPException, Request
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app import auth
    from app.db import Base
    from app.models import User, UserRole

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    investigator = User(
        email="investigator@example.com",
        password_hash="test",
        global_role=UserRole.investigator,
    )
    superuser = User(
        email="admin@example.com",
        password_hash="test",
        global_role=UserRole.superuser,
    )
    session.add_all([investigator, superuser])
    session.flush()

    @contextmanager
    def fake_db_session():
        yield session

    monkeypatch.setattr(auth, "db_session", fake_db_session)
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/organizations",
        "headers": [],
        "query_string": b"",
        "server": ("testserver", 80),
        "client": ("testclient", 50000),
        "scheme": "http",
        "path_params": {},
        "root_path": "",
    }
    try:
        for actor in (investigator, superuser):
            request = Request(dict(scope))
            try:
                auth.authorize_api_request(request, actor)
                assert False, "Legacy organization creation must be forbidden for every role"
            except HTTPException as error:
                assert error.status_code == 403
                assert "verified administrative provisioning" in error.detail
    finally:
        session.close()
        engine.dispose()


def test_administrative_entity_provisioning_binds_verified_manager_and_identifier(monkeypatch):
    from contextlib import contextmanager
    from fastapi import Request
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app import auth
    from app.db import Base
    from app.models import Organization, OrganizationMembership, MembershipRole, User, UserRole

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    manager = User(
        email="manager@institution.example",
        password_hash="test",
        global_role=UserRole.entity,
    )
    administrator = User(
        email="admin-provisioner@example.com",
        password_hash="test",
        global_role=UserRole.superuser,
    )
    session.add_all([manager, administrator])
    session.flush()

    @contextmanager
    def fake_db_session():
        yield session

    monkeypatch.setattr(auth, "db_session", fake_db_session)
    payload = auth.AdminOrganizationCreateRequest(
        name="Instituto de Investigación",
        slug="instituto-investigacion-001",
        manager_email="manager@institution.example",
    )
    request = Request({
        "type": "http",
        "method": "POST",
        "path": "/api/v1/admin/organizations",
        "headers": [],
        "query_string": b"",
        "server": ("testserver", 80),
        "client": ("testclient", 50000),
        "scheme": "http",
        "path_params": {},
        "root_path": "",
    })
    request.state.current_user_id = administrator.id
    try:
        result = auth.admin_create_organization(payload, request)
        organization = session.scalar(
            select(Organization).where(Organization.slug == "instituto-investigacion-001")
        )
        membership = session.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization.id,
                OrganizationMembership.user_id == manager.id,
            )
        )
        assert result["entity_identifier"] == "instituto-investigacion-001"
        assert result["manager_email"] == manager.email
        assert organization.contact_email == manager.email
        assert organization.verified_at is not None
        assert organization.verified_by_user_id == administrator.id
        assert organization.created_by_user_id == administrator.id
        assert membership is not None
        assert membership.role == MembershipRole.entity
    finally:
        session.close()
        engine.dispose()

def test_entity_provisioning_is_admin_only_and_exposed_in_admin_workspace():
    from app.main import app

    route = next(
        route for route in app.routes
        if getattr(route, "path", None) == "/api/v1/admin/organizations"
        and "POST" in (getattr(route, "methods", None) or set())
    )
    assert route is not None
    with TestClient(app) as client:
        login = client.get("/ui")
        workspace = client.get("/ui/workspace")
    assert login.status_code == 200
    assert 'value="entity"' not in login.text
    assert workspace.status_code == 200
    assert 'id="adminCreateOrganizationForm"' in workspace.text
    assert 'id="adminOrganizationIdentifier"' in workspace.text
    assert 'id="adminOrganizationEmail"' in workspace.text
    assert 'value="entity"' in workspace.text
    assert 'id="entityManagementPanel"' in workspace.text
    assert 'loadEntityManagement' in workspace.text
    assert "/admin/organizations" in workspace.text


def test_organization_scoped_investigation_creation_is_available_to_members():
    from app.main import app

    routes = {
        (route.path, method)
        for route in app.routes
        for method in (getattr(route, "methods", None) or set())
    }
    assert ("/api/v1/organizations", "GET") in routes
    assert ("/api/v1/investigations", "POST") in routes
    with TestClient(app) as client:
        response = client.get("/ui/workspace")
    assert response.status_code == 200
    assert 'id="investigationOrganization"' in response.text
    assert "loadInvestigationOrganizations" in response.text
    assert "organization_id" in response.text


def test_organization_investigator_cannot_access_colleague_investigation(monkeypatch):
    from contextlib import contextmanager
    from fastapi import HTTPException, Request
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app import auth
    from app.db import Base
    from app.models import (
        Job, JobStatus, MembershipRole, Organization,
        OrganizationMembership, User, UserRole,
    )

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    owner = User(email="owner@org.example.com", password_hash="test", global_role=UserRole.investigator)
    colleague = User(email="colleague@org.example.com", password_hash="test", global_role=UserRole.investigator)
    manager = User(email="manager@org.example.com", password_hash="test", global_role=UserRole.entity)
    session.add_all([owner, colleague, manager])
    session.flush()
    organization = Organization(
        name="Example Institution",
        slug="example-institution",
        created_by_user_id=manager.id,
    )
    session.add(organization)
    session.flush()
    session.add_all([
        OrganizationMembership(organization_id=organization.id, user_id=colleague.id, role=MembershipRole.investigator),
        OrganizationMembership(organization_id=organization.id, user_id=manager.id, role=MembershipRole.entity),
    ])
    job = Job(
        input_value="Confidential investigation",
        investigation_title="Confidential investigation",
        input_type="investigation",
        status=JobStatus.draft,
        owner_user_id=owner.id,
        organization_id=organization.id,
    )
    session.add(job)
    session.flush()

    @contextmanager
    def fake_db_session():
        yield session

    monkeypatch.setattr(auth, "db_session", fake_db_session)
    scope = {
        "type": "http",
        "method": "GET",
        "path": f"/api/v1/jobs/{job.id}",
        "headers": [],
        "query_string": b"",
        "server": ("testserver", 80),
        "client": ("testclient", 50000),
        "scheme": "http",
        "path_params": {"job_id": job.id},
        "root_path": "",
    }
    try:
        with __import__("pytest").raises(HTTPException) as error:
            auth.authorize_api_request(Request(dict(scope)), colleague)
        assert error.value.status_code == 404
        # Entity managers can inspect the same organizational investigation,
        # but mutation routes are rejected by the same central policy.
        auth.authorize_api_request(Request(dict(scope)), manager)
        mutation_scope = dict(scope, method="POST")
        with __import__("pytest").raises(HTTPException) as mutation_error:
            auth.authorize_api_request(Request(mutation_scope), manager)
        assert mutation_error.value.status_code == 403
    finally:
        session.close()
        engine.dispose()


def test_job_listing_exposes_org_investigations_only_to_entity_managers(monkeypatch):
    from contextlib import contextmanager
    from fastapi import FastAPI, Request
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app import api
    from app.db import Base
    from app.models import (
        Job, JobStatus, MembershipRole, Organization,
        OrganizationMembership, User, UserRole,
    )

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    owner = User(email="owner2@org.example.com", password_hash="test", global_role=UserRole.investigator)
    colleague = User(email="colleague2@org.example.com", password_hash="test", global_role=UserRole.investigator)
    manager = User(email="manager2@org.example.com", password_hash="test", global_role=UserRole.entity)
    session.add_all([owner, colleague, manager])
    session.flush()
    organization = Organization(name="Example Institution 2", slug="example-institution-2", created_by_user_id=manager.id)
    session.add(organization)
    session.flush()
    session.add_all([
        OrganizationMembership(organization_id=organization.id, user_id=colleague.id, role=MembershipRole.investigator),
        OrganizationMembership(organization_id=organization.id, user_id=manager.id, role=MembershipRole.entity),
    ])
    session.add(Job(
        input_value="Org investigation",
        investigation_title="Org investigation",
        input_type="investigation",
        status=JobStatus.draft,
        owner_user_id=owner.id,
        organization_id=organization.id,
    ))
    session.flush()
    actor = {"id": colleague.id}

    @contextmanager
    def fake_db_session():
        yield session

    def fake_auth(request: Request):
        request.state.current_user_id = actor["id"]

    monkeypatch.setattr(api, "db_session", fake_db_session)
    test_app = FastAPI()
    test_app.include_router(api.router)
    test_app.dependency_overrides[api.authorize_api_request] = fake_auth
    try:
        with TestClient(test_app) as client:
            assert client.get("/api/v1/jobs").json() == []
            actor["id"] = manager.id
            visible = client.get("/api/v1/jobs")
            assert visible.status_code == 200
            assert len(visible.json()) == 1
            assert visible.json()[0]["investigation_title"] == "Org investigation"
            assert visible.json()[0]["can_edit"] is False
    finally:
        session.close()
        engine.dispose()


def test_entity_role_cannot_be_self_registered(monkeypatch):
    from fastapi import HTTPException

    from app import auth

    monkeypatch.setattr(auth, "_secret", lambda: "test-secret")
    payload = auth.RegisterRequest(
        email="self-claimed-entity@example.com",
        password="long-enough-test-password",
        global_role="entity",
    )
    try:
        auth.register(payload)
        assert False, "Entity accounts must be provisioned by an administrator"
    except HTTPException as error:
        assert error.status_code == 422
        assert "investigator or user" in error.detail


def test_admin_verification_preserves_existing_organization_and_investigations(monkeypatch):
    from contextlib import contextmanager
    from fastapi import Request
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool

    from app import auth
    from app.db import Base
    from app.models import (
        Job, JobStatus, MembershipRole, Organization,
        OrganizationMembership, User, UserRole,
    )

    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    original_creator = User(
        email="legacy-creator@example.com",
        password_hash="test",
        global_role=UserRole.investigator,
    )
    manager = User(
        email="verified-entity@example.com",
        password_hash="test",
        global_role=UserRole.entity,
    )
    administrator = User(
        email="verifier@example.com",
        password_hash="test",
        global_role=UserRole.superuser,
    )
    session.add_all([original_creator, manager, administrator])
    session.flush()
    organization = Organization(
        name="Legacy Institution",
        slug="legacy-institution-001",
        created_by_user_id=original_creator.id,
    )
    session.add(organization)
    session.flush()
    organization_id = organization.id
    job = Job(
        input_value="Preserve this investigation",
        investigation_title="Preserve this investigation",
        input_type="investigation",
        status=JobStatus.draft,
        owner_user_id=original_creator.id,
        organization_id=organization.id,
    )
    session.add(job)
    session.flush()
    job_id = job.id

    @contextmanager
    def fake_db_session():
        yield session

    monkeypatch.setattr(auth, "db_session", fake_db_session)
    request = Request({
        "type": "http",
        "method": "POST",
        "path": "/api/v1/admin/organizations",
        "headers": [],
        "query_string": b"",
        "server": ("testserver", 80),
        "client": ("testclient", 50000),
        "scheme": "http",
        "path_params": {},
        "root_path": "",
    })
    request.state.current_user_id = administrator.id
    try:
        auth.admin_create_organization(
            auth.AdminOrganizationCreateRequest(
                name="Verified Legacy Institution",
                slug="legacy-institution-001",
                manager_email="verified-entity@example.com",
            ),
            request,
        )
        preserved_org = session.get(Organization, organization_id)
        preserved_job = session.get(Job, job_id)
        membership = session.scalar(select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.user_id == manager.id,
        ))
        assert preserved_org is not None
        assert preserved_org.name == "Verified Legacy Institution"
        assert preserved_org.created_by_user_id == original_creator.id
        assert preserved_org.verified_by_user_id == administrator.id
        assert preserved_org.contact_email == manager.email
        assert preserved_job is not None
        assert preserved_job.organization_id == organization_id
        assert membership is not None and membership.role == MembershipRole.entity
    finally:
        session.close()
        engine.dispose()



def test_merge_requires_review_and_invalidates_review_when_copy_changes(monkeypatch):
    from contextlib import contextmanager
    from fastapi import FastAPI, Request
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from app import api
    from app.db import Base
    from app.models import Job, JobStatus, User, UserRole

    engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    owner = User(email="review-owner@example.com", password_hash="test", global_role=UserRole.investigator)
    collaborator = User(email="review-collab@example.com", password_hash="test", global_role=UserRole.investigator)
    session.add_all([owner, collaborator]); session.flush()
    original = Job(input_value="base", investigation_title="base", input_type="investigation", status=JobStatus.draft, owner_user_id=owner.id)
    session.add(original); session.flush()
    original_id = original.id

    @contextmanager
    def fake_db_session():
        yield session

    def fake_auth(request: Request):
        request.state.current_user_id = owner.id
    monkeypatch.setattr(api, "db_session", fake_db_session)
    test_app = FastAPI(); test_app.include_router(api.router)
    test_app.dependency_overrides[api.authorize_api_request] = fake_auth
    with TestClient(test_app) as client:
        created = client.post(f"/api/v1/jobs/{original_id}/shares", json={"email": collaborator.email, "permission": "edit"})
        assert created.status_code == 201, created.text
        share_id = created.json()["share_id"]
        assert client.post(f"/api/v1/jobs/{original_id}/shares/{share_id}/merge").status_code == 409
        review = client.get(f"/api/v1/jobs/{original_id}/shares/{share_id}/review")
        assert review.status_code == 200
        assert client.post(f"/api/v1/jobs/{original_id}/shares/{share_id}/review", json={"snapshot_token": review.json()["snapshot_token"]}).status_code == 200
        share = session.query(api.InvestigationShare).filter_by(id=share_id).one()
        session.get(Job, share.shared_job_id).notes = "changed after review"
        session.flush()
        stale_merge = client.post(f"/api/v1/jobs/{original_id}/shares/{share_id}/merge")
        assert stale_merge.status_code == 409, stale_merge.text
        review = client.get(f"/api/v1/jobs/{original_id}/shares/{share_id}/review")
        assert review.status_code == 200
        assert client.post(f"/api/v1/jobs/{original_id}/shares/{share_id}/review", json={"snapshot_token": review.json()["snapshot_token"]}).status_code == 200
        merged = client.post(f"/api/v1/jobs/{original_id}/shares/{share_id}/merge")
        assert merged.status_code == 200, merged.text
        assert session.get(Job, original_id).notes == "changed after review"
    session.close(); engine.dispose()


def test_original_investigator_can_read_shared_copy_comments(monkeypatch):
    from contextlib import contextmanager
    from fastapi import FastAPI, Request
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from app import api
    from app.db import Base
    from app.models import InvestigationShare, InvestigationComment, Job, JobStatus, User, UserRole

    engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    owner = User(email="thread-owner@example.com", password_hash="test", global_role=UserRole.investigator)
    collaborator = User(email="thread-collab@example.com", password_hash="test", global_role=UserRole.investigator)
    session.add_all([owner, collaborator]); session.flush()
    original = Job(input_value="base", investigation_title="base", input_type="investigation", status=JobStatus.draft, owner_user_id=owner.id)
    copy = Job(input_value="base", investigation_title="base", input_type="investigation", status=JobStatus.draft, owner_user_id=collaborator.id)
    session.add_all([original, copy]); session.flush()
    share = InvestigationShare(original_job_id=original.id, shared_job_id=copy.id, owner_user_id=owner.id, collaborator_user_id=collaborator.id, permission="edit", base_snapshot={"version": 1, "tables": []}, id_map={})
    session.add(share); session.flush()
    session.add(InvestigationComment(share_id=share.id, author_user_id=collaborator.id, body="Please review this change")); session.flush()

    @contextmanager
    def fake_db_session():
        yield session

    def fake_auth(request: Request):
        request.state.current_user_id = owner.id
    monkeypatch.setattr(api, "db_session", fake_db_session)
    test_app = FastAPI(); test_app.include_router(api.router)
    test_app.dependency_overrides[api.authorize_api_request] = fake_auth
    with TestClient(test_app) as client:
        shares = client.get(f"/api/v1/jobs/{original.id}/shares")
        assert shares.status_code == 200, shares.text
        comments = client.get(f"/api/v1/shares/{share.id}/comments")
        assert comments.status_code == 200, comments.text
        assert comments.json()[0]["body"] == "Please review this change"
    session.close(); engine.dispose()


def test_investigation_workspace_exposes_review_before_merge_controls():
    with TestClient(app) as client:
        response = client.get("/ui/job/example")
    assert response.status_code == 200
    assert "Review changes" in response.text
    assert "Mark this version as reviewed" in response.text
    assert "Pending review" in response.text



def test_three_way_merge_preserves_non_overlapping_owner_and_collaborator_changes(monkeypatch):
    from contextlib import contextmanager
    from fastapi import FastAPI, Request
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from app import api
    from app.db import Base
    from app.models import Job, JobStatus, User, UserRole

    engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    owner = User(email="merge-owner@example.com", password_hash="test", global_role=UserRole.investigator)
    collaborator = User(email="merge-collab@example.com", password_hash="test", global_role=UserRole.investigator)
    session.add_all([owner, collaborator]); session.flush()
    original = Job(input_value="base", investigation_title="base title", notes=None, input_type="investigation", status=JobStatus.draft, owner_user_id=owner.id)
    session.add(original); session.flush()
    original_id = original.id

    @contextmanager
    def fake_db_session():
        yield session

    def fake_auth(request: Request):
        request.state.current_user_id = owner.id
    monkeypatch.setattr(api, "db_session", fake_db_session)
    test_app = FastAPI(); test_app.include_router(api.router)
    test_app.dependency_overrides[api.authorize_api_request] = fake_auth
    with TestClient(test_app) as client:
        created = client.post(f"/api/v1/jobs/{original_id}/shares", json={"email": collaborator.email, "permission": "edit"})
        assert created.status_code == 201, created.text
        share_id = created.json()["share_id"]
        share = session.get(api.InvestigationShare, share_id)
        copy = session.get(Job, share.shared_job_id)
        original.notes = "owner-only notes change"
        copy.investigation_title = "collaborator title change"
        session.flush()
        review = client.get(f"/api/v1/jobs/{original_id}/shares/{share_id}/review")
        assert review.status_code == 200
        assert client.post(f"/api/v1/jobs/{original_id}/shares/{share_id}/review", json={"snapshot_token": review.json()["snapshot_token"]}).status_code == 200
        merged = client.post(f"/api/v1/jobs/{original_id}/shares/{share_id}/merge")
        assert merged.status_code == 200, merged.text
        refreshed_original = session.get(Job, original_id)
        refreshed_copy = session.get(Job, share.shared_job_id)
        assert refreshed_original.notes == "owner-only notes change"
        assert refreshed_original.investigation_title == "collaborator title change"
        assert refreshed_copy.notes == "owner-only notes change"
        assert refreshed_copy.investigation_title == "collaborator title change"
        assert merged.json()["branch_synchronized"] is True
    session.close(); engine.dispose()


def test_three_way_merge_rejects_conflicting_edits(monkeypatch):
    from contextlib import contextmanager
    from fastapi import FastAPI, Request
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from app import api
    from app.db import Base
    from app.models import Job, JobStatus, User, UserRole

    engine = create_engine("sqlite+pysqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine, expire_on_commit=False)()
    owner = User(email="conflict-owner@example.com", password_hash="test", global_role=UserRole.investigator)
    collaborator = User(email="conflict-collab@example.com", password_hash="test", global_role=UserRole.investigator)
    session.add_all([owner, collaborator]); session.flush()
    original = Job(input_value="base", investigation_title="base", notes="same base", input_type="investigation", status=JobStatus.draft, owner_user_id=owner.id)
    session.add(original); session.flush()
    original_id = original.id

    @contextmanager
    def fake_db_session():
        yield session

    def fake_auth(request: Request):
        request.state.current_user_id = owner.id
    monkeypatch.setattr(api, "db_session", fake_db_session)
    test_app = FastAPI(); test_app.include_router(api.router)
    test_app.dependency_overrides[api.authorize_api_request] = fake_auth
    with TestClient(test_app) as client:
        created = client.post(f"/api/v1/jobs/{original_id}/shares", json={"email": collaborator.email, "permission": "edit"})
        assert created.status_code == 201, created.text
        share_id = created.json()["share_id"]
        share = session.get(api.InvestigationShare, share_id)
        copy = session.get(Job, share.shared_job_id)
        original.notes = "owner version"
        copy.notes = "collaborator version"
        session.flush()
        review = client.get(f"/api/v1/jobs/{original_id}/shares/{share_id}/review")
        assert review.status_code == 200
        assert client.post(f"/api/v1/jobs/{original_id}/shares/{share_id}/review", json={"snapshot_token": review.json()["snapshot_token"]}).status_code == 200
        response = client.post(f"/api/v1/jobs/{original_id}/shares/{share_id}/merge")
        assert response.status_code == 409, response.text
        assert "conflicts" in response.json()["detail"]
        assert session.get(Job, original_id).notes == "owner version"
    session.close(); engine.dispose()
