from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse
from sqlalchemy import inspect, text

from app.api import router
from app.auth import admin_router, auth_router, organization_router
from app.db import Base, engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    # Small forward-compatible schema migration for existing Codespaces databases.
    with engine.begin() as connection:
        if engine.dialect.name == "postgresql":
            connection.execute(text("ALTER TYPE jobstatus ADD VALUE IF NOT EXISTS 'draft'"))
        # Enforce a single platform administrator in every supported database.
        # If legacy data has duplicates, startup fails rather than silently changing roles.
        connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_users_single_superuser ON users (global_role) WHERE global_role = 'superuser'"))
        columns = {column["name"] for column in inspect(connection).get_columns("jobs")}
        if "investigation_title" not in columns:
            connection.execute(text("ALTER TABLE jobs ADD COLUMN investigation_title TEXT"))
        if "notes" not in columns:
            connection.execute(text("ALTER TABLE jobs ADD COLUMN notes TEXT"))
    yield


app = FastAPI(title="OSINT MVP", version="0.1.0", lifespan=lifespan)
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(organization_router)
app.include_router(router)


@app.get("/", include_in_schema=False)
@app.get("/ui", include_in_schema=False)
def access_ui():
    """Serve the authentication and personal investigation landing page."""
    return FileResponse(
        Path(__file__).resolve().parent / "static" / "index.html",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache"},
    )


@app.get("/ui/workspace", include_in_schema=False)
def workspace_ui():
    """Serve the authenticated workspace dashboard as a dedicated page."""
    return FileResponse(
        Path(__file__).resolve().parent / "static" / "workspace.html",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache"},
    )


@app.get("/ui/job/{job_id}", include_in_schema=False)
@app.get("/ui/graph/{job_id}", include_in_schema=False)
def investigator_ui(job_id: str):
    """Serve the investigator workspace for an OSINT job."""
    return FileResponse(
        Path(__file__).resolve().parent / "static" / "graph.html",
        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache"},
    )



@app.get("/ui/papiro.css", include_in_schema=False)
def papiro_styles():
    return FileResponse(
        Path(__file__).resolve().parent / "static" / "papiro.css",
        media_type="text/css",
        headers={"Cache-Control": "no-cache"},
    )


@app.get("/ui/papiro-og.svg", include_in_schema=False)
def papiro_social_image():
    return FileResponse(
        Path(__file__).resolve().parent / "static" / "papiro-og.svg",
        media_type="image/svg+xml",
        headers={"Cache-Control": "no-cache"},
    )


@app.get("/health")
def health():
    return {"status": "ok"}
