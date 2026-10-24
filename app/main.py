from app.firebase_auth import verify_firebase_id_token, enforce_email_verification, upsert_firebase_user
import json
import logging
import os
import secrets
import urllib.parse
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime
from pathlib import Path
import re

logger = logging.getLogger(__name__)

from dotenv import load_dotenv
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import distinct, func, or_, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware
from starlette.responses import JSONResponse, RedirectResponse

from app.database import Base, engine, get_db
from app.config import is_production, is_within_allowed_root
from datetime import timedelta
from app.models import Finding, GitHubWebhookDelivery, Notification, Scan
from app.models import FindingLifecycle, User, UserInstallation, UserRepository, EmailVerificationToken
from app.auth_service import (
    derive_display_name,
    hash_password,
    verify_password,
    validate_password_strength,
    normalize_email,
    generate_verification_token,
    hash_token,
    mask_email,
)
from app.email_service import send_verification_email, is_email_service_configured
from app.finding_lifecycle import process_completed_scan_lifecycle
from app.notification_service import create_scan_notifications
from app.security_gate import persist_security_gate
from app.scanner_service import (
    run_code_scan,
    run_dependency_scan,
    run_secret_scan,
    run_container_scan,
)
from app.github_service import (
    get_repository,
    download_repository,
)
from app.ai_analyzer import analyze_finding
from app.github_webhook import (
    get_webhook_secret,
    verify_github_signature,
    extract_push_event_metadata,
    extract_pull_request_event_metadata,
    log_webhook_event,
)
from app.scan_service import (
    run_github_repository_scan,
    run_github_repository_scan_background,
)
from app.github_checks import get_check_run_token
from app.github_app import get_github_app_status, get_repository_installation
from app.celery_app import get_queue_status
from app.tasks import run_github_repository_scan_task


load_dotenv()

app = FastAPI(
    title="Rakshak AI-Powered DevSecOps Threat Detection Platform",
    version="1.0.0",
)

# Compatibility bookkeeping only; durable PostgreSQL delivery uniqueness is
# the source of truth for deduplication.
_processed_deliveries: set[str] = set()


# ============================================================
# FRONTEND URL & CORS
# ============================================================

def get_frontend_url() -> str:
    """Return the configured frontend base URL or default to localhost:5173."""
    url = os.getenv("FRONTEND_URL", "http://localhost:5173").strip()
    if url and not url.startswith("http://") and not url.startswith("https://"):
        url = f"https://{url}"
    if "rakshak-frontend.onrender.com" in url:
        url = "https://rakshak-frontend-yoem.onrender.com"
    return url.rstrip("/")


def get_cors_origins() -> list[str]:
    """Resolve allowed CORS origins from environment and defaults."""
    raw = os.getenv("CORS_ALLOWED_ORIGINS")
    origins = [item.strip() for item in raw.split(",") if item.strip()] if raw else []

    frontend_url = get_frontend_url()
    if frontend_url and frontend_url not in origins:
        origins.append(frontend_url)

    for def_orig in ("http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000", "http://127.0.0.1:3000"):
        if def_orig not in origins:
            origins.append(def_orig)

    return origins


app.add_middleware(
    CORSMiddleware,
    allow_origins=get_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    frontend_url = get_frontend_url()
    connect_sources = "'self' https: http://localhost:5173 http://127.0.0.1:5173 http://localhost:8000 http://127.0.0.1:8000"
    if frontend_url and frontend_url not in connect_sources:
        connect_sources += f" {frontend_url}"

    response.headers["Content-Security-Policy"] = (
        f"default-src 'self'; connect-src {connect_sources}; img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    )
    is_https = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    if is_production() and is_https:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ============================================================
# SESSION
# ============================================================

SESSION_SECRET = os.getenv("SESSION_SECRET")

if not SESSION_SECRET:
    raise RuntimeError("SESSION_SECRET is not set")

session_cookie_secure = os.getenv("SESSION_COOKIE_SECURE")
is_prod = is_production()
https_only = session_cookie_secure.lower() == "true" if session_cookie_secure is not None else is_prod

same_site_env = os.getenv("SESSION_COOKIE_SAME_SITE")
if same_site_env:
    same_site = same_site_env.lower()
elif https_only:
    same_site = "none"
else:
    same_site = "lax"

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    https_only=https_only,
    same_site=same_site,
)


# ============================================================
# IDENTITY & WORKSPACE OWNERSHIP
# ============================================================

def upsert_github_user(db: Session, github_user: dict, current_user_id: int | None = None) -> User:
    """Upsert or link a GitHub user into the Rakshak User model.

    If current_user_id is provided, link GitHub identity to that specific active User.
    Otherwise, search by github_user_id, then by email match.
    Prevents cross-account collisions if a GitHub account is already tied to another user.
    """
    github_user_id = github_user.get("id")

    if github_user_id in (None, ""):
        raise HTTPException(
            status_code=502,
            detail="GitHub user id missing",
        )

    try:
        github_user_id = int(github_user_id)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=502,
            detail="GitHub user id is invalid",
        )

    github_login = str(github_user.get("login") or f"github-{github_user_id}")
    now = datetime.utcnow()
    raw_email = github_user.get("email")
    normalized_email = raw_email.strip().lower() if raw_email and isinstance(raw_email, str) and raw_email.strip() else None

    # Check if this GitHub identity is already owned by any user
    existing_gh_owner = (
        db.query(User)
        .filter(User.github_user_id == github_user_id)
        .first()
    )

    user = None
    if current_user_id is not None:
        user = db.query(User).filter(User.id == current_user_id).first()
        if user is not None:
            if existing_gh_owner is not None and existing_gh_owner.id != user.id:
                raise HTTPException(
                    status_code=409,
                    detail=f"This GitHub account (@{github_login}) is already linked to another Rakshak account.",
                )

    if user is None:
        user = existing_gh_owner

    if user is None and normalized_email:
        # Check if an existing verified email user matches
        user = (
            db.query(User)
            .filter(User.email == normalized_email, User.github_user_id.is_(None))
            .first()
        )

    if user is None:
        user = User(
            github_user_id=github_user_id,
            github_login=github_login,
            email=normalized_email,
            name=github_user.get("name"),
            avatar_url=github_user.get("avatar_url"),
            html_url=github_user.get("html_url"),
            is_verified=True,
            created_at=now,
            last_seen_at=now,
        )
        db.add(user)
    else:
        user.github_user_id = github_user_id
        user.github_login = github_login
        if normalized_email and not user.email:
            user.email = normalized_email
        if github_user.get("name") and not user.name:
            user.name = github_user.get("name")
        if github_user.get("avatar_url"):
            user.avatar_url = github_user.get("avatar_url")
        if github_user.get("html_url"):
            user.html_url = github_user.get("html_url")
        user.is_verified = True
        user.last_seen_at = now

    db.commit()
    db.refresh(user)
    return user


def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    """Resolve the authenticated Rakshak workspace from Firebase ID token or session.

    1. Checks Authorization: Bearer <token> for Firebase ID token authentication.
       - Validates token with Firebase Admin SDK.
       - Enforces provider-aware email verification.
       - Maps/upserts User in database.
    2. Falls back to session user_pk (for GitHub OAuth / session flows).
    Returns 401 when unauthenticated.
    """
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        decoded = verify_firebase_id_token(token)
        enforce_email_verification(decoded)
        return upsert_firebase_user(db, decoded)

    user_pk = request.session.get("user_pk")

    user = None
    if user_pk is not None:
        try:
            user = (
                db.query(User)
                .filter(User.id == int(user_pk))
                .first()
            )
        except (TypeError, ValueError):
            user = None

    if user is None or not user.is_verified:
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )

    return user


def _resolve_webhook_workspace(
    db: Session,
    installation_id: int | None,
    repository_full_name: str | None,
) -> int | None:
    """Resolve the owning Rakshak workspace for an inbound webhook event.

    Resolution order:
      1. GitHub App installation -> workspace mapping (authoritative).
      2. Repository -> workspace mapping, only when the repository is
         associated with EXACTLY ONE workspace (never ambiguous).

    The GitHub repository owner's login is NEVER used as a Rakshak identity.
    Returns ``None`` when ownership cannot be safely established.
    """
    if installation_id:
        try:
            link = (
                db.query(UserInstallation)
                .filter(UserInstallation.installation_id == int(installation_id))
                .first()
            )
            if link is not None:
                return link.user_id
        except (TypeError, ValueError):
            pass

    if repository_full_name:
        rows = (
            db.query(UserRepository.user_id)
            .filter(UserRepository.repository_full_name == repository_full_name)
            .distinct()
            .all()
        )
        user_ids = {row[0] for row in rows}
        if len(user_ids) == 1:
            return user_ids.pop()

    return None


def _link_manual_scan_workspace(
    db: Session,
    user: User,
    owner: str,
    repo: str,
) -> None:
    """Record the workspace/repository (and installation) mapping after a
    successful manual OAuth repository scan.

    The installation ID is resolved through GitHub's API (App JWT) — never
    invented. Best-effort only: mapping failures never fail the scan request.
    """
    repository_full_name = f"{owner}/{repo}"
    now = datetime.utcnow()

    try:
        repo_link = (
            db.query(UserRepository)
            .filter(
                UserRepository.user_id == user.id,
                UserRepository.repository_full_name == repository_full_name,
            )
            .first()
        )

        if repo_link is None:
            repo_link = UserRepository(
                user_id=user.id,
                repository_full_name=repository_full_name,
                created_at=now,
                last_seen_at=now,
            )
            db.add(repo_link)
        else:
            repo_link.last_seen_at = now

        installation_id = get_repository_installation(owner, repo)

        if installation_id:
            installation_link = (
                db.query(UserInstallation)
                .filter(UserInstallation.installation_id == installation_id)
                .first()
            )

            if installation_link is None:
                installation_link = UserInstallation(
                    installation_id=installation_id,
                    user_id=user.id,
                    created_at=now,
                    last_seen_at=now,
                )
                db.add(installation_link)
                repo_link.installation_id = installation_id
            elif installation_link.user_id == user.id:
                installation_link.last_seen_at = now
                repo_link.installation_id = installation_id
            # An installation already mapped to a different workspace is left
            # untouched (first workspace to establish the mapping owns it).

        db.commit()

    except Exception as exc:
        db.rollback()
        logger.warning(
            "[Workspace] Failed to record repository/installation mapping for %s/%s: %s",
            owner,
            repo,
            str(exc),
        )


# ============================================================
# MODELS
# ============================================================

class ScanRequest(BaseModel):
    target_path: str = Field(min_length=1, max_length=500)
    code_scanning: bool = True
    dependency_scanning: bool = True
    secret_detection: bool = True
    container_scanning: bool = False
    container_image: str | None = Field(default=None, max_length=300)

    @field_validator("target_path")
    @classmethod
    def validate_target_path(cls, value: str) -> str:
        path = Path(value).expanduser()
        if not is_within_allowed_root(path):
            raise ValueError("target_path is outside the configured scan roots")
        return str(path)

    @field_validator("container_image")
    @classmethod
    def validate_container_image(cls, value: str | None) -> str | None:
        if value and (any(char.isspace() for char in value) or any(char in value for char in ";&|$`\n\r")):
            raise ValueError("container_image contains invalid characters")
        return value


class GitHubScanRequest(BaseModel):
    owner: str = Field(min_length=1, max_length=100)
    repo: str = Field(min_length=1, max_length=100)
    ref: str | None = Field(default=None, max_length=255)
    code_scanning: bool = True
    dependency_scanning: bool = True
    secret_detection: bool = True
    container_scanning: bool = False
    container_image: str | None = Field(default=None, max_length=300)

    @field_validator("owner", "repo")
    @classmethod
    def validate_github_name(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", value):
            raise ValueError("invalid GitHub owner or repository name")
        return value

    @field_validator("ref")
    @classmethod
    def validate_ref(cls, value: str | None) -> str | None:
        if value and (".." in value or "\x00" in value or any(char in value for char in "\r\n")):
            raise ValueError("invalid Git ref")
        return value

    @field_validator("container_image")
    @classmethod
    def validate_github_container_image(cls, value: str | None) -> str | None:
        if value and (any(char.isspace() for char in value) or any(char in value for char in ";&|$`\n\r")):
            raise ValueError("container_image contains invalid characters")
        return value


def _validate_github_name(value: str, label: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", value or ""):
        raise HTTPException(status_code=422, detail=f"Invalid GitHub {label}")
    return value


def _validate_untrusted_ref(value: str | None) -> str | None:
    if value and (len(value) > 255 or ".." in value or "\x00" in value or any(char in value for char in "\r\n")):
        raise HTTPException(status_code=422, detail="Invalid Git ref")
    return value


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "rakshak-backend",
    }


@app.get("/ready")
def readiness(db: Session = Depends(get_db)):
    """Lightweight readiness probe that checks database connectivity only."""
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        raise HTTPException(status_code=503, detail="Database is unavailable")
    return {"status": "ready", "database": "ok"}


# ============================================================
# GITHUB OAUTH
# ============================================================

@app.get("/api/auth/github")
def github_login(request: Request):
    client_id = os.getenv("GITHUB_CLIENT_ID")
    redirect_uri = os.getenv("GITHUB_REDIRECT_URI")

    if not client_id or not redirect_uri:
        raise HTTPException(
            status_code=500,
            detail="GitHub OAuth configuration is missing",
        )

    # Generate high-entropy state token for CSRF defense
    oauth_state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = oauth_state

    # Include prompt=select_account so the user can choose which GitHub account to authorize
    params = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "repo read:user user:email",
            "state": oauth_state,
            "prompt": "select_account",
        }
    )

    github_url = (
        "https://github.com/login/oauth/authorize?"
        + params
    )

    return RedirectResponse(url=github_url)


@app.get("/api/auth/github/callback")
def github_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    db: Session = Depends(get_db),
):
    if not code:
        raise HTTPException(
            status_code=400,
            detail="GitHub authorization code is missing",
        )

    # CSRF state parameter validation
    expected_state = request.session.pop("oauth_state", None)
    frontend_url = get_frontend_url()
    if not state or not expected_state or state != expected_state:
        logger.warning("GitHub OAuth callback state mismatch or expired")
        return RedirectResponse(
            url=f"{frontend_url}/repositories?error=oauth_state_invalid"
        )

    client_id = os.getenv("GITHUB_CLIENT_ID")
    client_secret = os.getenv("GITHUB_CLIENT_SECRET")
    redirect_uri = os.getenv("GITHUB_REDIRECT_URI")

    if not client_id or not client_secret or not redirect_uri:
        raise HTTPException(
            status_code=500,
            detail="GitHub OAuth configuration is missing",
        )

    token_data = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
        }
    ).encode()

    token_request = urllib.request.Request(
        "https://github.com/login/oauth/access_token",
        data=token_data,
        headers={
            "Accept": "application/json",
            "User-Agent": "Rakshak",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            token_request,
            timeout=30,
        ) as response:
            token_response = json.loads(
                response.read().decode()
            )

    except urllib.error.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail="GitHub token exchange failed",
        )

    access_token = token_response.get("access_token")

    if not access_token:
        raise HTTPException(
            status_code=502,
            detail="GitHub did not return an access token",
        )

    # Get GitHub user information.
    user_request = urllib.request.Request(
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Rakshak",
        },
    )

    try:
        with urllib.request.urlopen(
            user_request,
            timeout=30,
        ) as response:
            github_user = json.loads(
                response.read().decode()
            )

    except urllib.error.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail="Failed to fetch GitHub user",
        )

    current_user_pk = request.session.get("user_pk")
    try:
        user = upsert_github_user(db, github_user, current_user_id=int(current_user_pk) if current_user_pk else None)
    except HTTPException as exc:
        if exc.status_code == 409:
            return RedirectResponse(
                url=f"{frontend_url}/repositories?error=github_already_linked"
            )
        raise

    # Store authenticated session and GitHub credentials for this user
    request.session["user_pk"] = user.id
    request.session["github_access_token"] = access_token
    request.session["github_user"] = {
        "id": github_user.get("id"),
        "login": github_user.get("login"),
        "name": github_user.get("name"),
        "avatar_url": github_user.get("avatar_url"),
        "html_url": github_user.get("html_url"),
    }

    return RedirectResponse(
        url=f"{frontend_url}/repositories?connected=true"
    )


@app.post("/api/auth/github/disconnect")
def disconnect_github(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Disconnect and unlink GitHub account from the current Rakshak user."""
    current_user.github_user_id = None
    current_user.github_login = None
    db.commit()

    request.session.pop("github_access_token", None)
    request.session.pop("github_user", None)

    return {
        "success": True,
        "message": "GitHub account disconnected successfully.",
    }


# ============================================================
# AUTHENTICATION (EMAIL & PASSWORD + EMAIL VERIFICATION)
# ============================================================

class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    name: str | None = Field(default=None, max_length=255)


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=128)


class VerifyEmailRequest(BaseModel):
    token: str = Field(min_length=1, max_length=256)


class ResendVerificationRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)


@app.post("/api/auth/register", status_code=201)
def register(
    req: RegisterRequest,
    db: Session = Depends(get_db),
):
    try:
        normalized_email = normalize_email(req.email)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    valid_pw, pw_err = validate_password_strength(req.password)
    if not valid_pw:
        raise HTTPException(status_code=422, detail=pw_err or "Password does not meet requirements.")

    now = datetime.utcnow()

    existing_user = db.query(User).filter(User.email == normalized_email).first()

    if existing_user and existing_user.is_verified:
        raise HTTPException(
            status_code=409,
            detail="An account with this email address is already registered.",
        )

    raw_token, token_hash = generate_verification_token()
    token_expires_at = now + timedelta(minutes=15)

    if existing_user and not existing_user.is_verified:
        existing_user.hashed_password = hash_password(req.password)
        if req.name:
            existing_user.name = req.name.strip()
        user = existing_user
        db.query(EmailVerificationToken).filter(
            EmailVerificationToken.user_id == user.id,
            EmailVerificationToken.token_type == "email_verification",
            EmailVerificationToken.used_at.is_(None),
        ).update({"used_at": now}, synchronize_session=False)
    else:
        user = User(
            email=normalized_email,
            hashed_password=hash_password(req.password),
            name=req.name.strip() if req.name else None,
            is_verified=False,
            created_at=now,
            last_seen_at=now,
        )
        db.add(user)
        db.flush()

    verification_token = EmailVerificationToken(
        user_id=user.id,
        token_hash=token_hash,
        token_type="email_verification",
        expires_at=token_expires_at,
        created_at=now,
    )
    db.add(verification_token)

    email_result = send_verification_email(
        to_email=normalized_email,
        raw_token=raw_token,
        user_name=user.name,
    )

    if not email_result.get("success"):
        db.rollback()
        err_msg = email_result.get("error") or "Failed to deliver verification email."
        raise HTTPException(
            status_code=502,
            detail=f"Registration failed: {err_msg}",
        )

    db.commit()

    return {
        "success": True,
        "message": "Verification email sent. Please check your inbox.",
        "email": mask_email(normalized_email),
    }


@app.post("/api/auth/login")
def login(
    req: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    try:
        normalized_email = normalize_email(req.email)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    user = db.query(User).filter(User.email == normalized_email).first()

    if not user or not user.hashed_password:
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")

    if not user.is_verified:
        return JSONResponse(
            status_code=403,
            content={
                "detail": "Email verification required. Please check your inbox.",
                "error_code": "EMAIL_UNVERIFIED",
                "email": user.email,
            },
        )

    now = datetime.utcnow()
    user.last_seen_at = now
    db.commit()

    request.session.clear()
    request.session["user_pk"] = user.id

    display_name = user.name or derive_display_name(user.email, user.name)
    return {
        "authenticated": True,
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name or display_name,
            "display_name": display_name,
            "login": user.github_login,
            "avatar_url": user.avatar_url,
            "html_url": user.html_url,
            "github_user_id": user.github_user_id,
            "github_login": user.github_login,
            "is_verified": user.is_verified,
        },
        "github_connected": False,
        "github_user": None,
    }


@app.post("/api/auth/verify-email")
def verify_email_endpoint(
    req: VerifyEmailRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    token_str = req.token.strip()
    if not token_str:
        raise HTTPException(status_code=400, detail="Verification token is required.")

    computed_hash = hash_token(token_str)
    now = datetime.utcnow()

    token_record = (
        db.query(EmailVerificationToken)
        .filter(
            EmailVerificationToken.token_hash == computed_hash,
            EmailVerificationToken.token_type == "email_verification",
        )
        .first()
    )

    if not token_record:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token.")

    if token_record.used_at is not None:
        raise HTTPException(status_code=400, detail="Verification link has already been used. Please log in.")

    if token_record.attempts >= 5:
        raise HTTPException(status_code=400, detail="Verification attempts exceeded limit. Please request a new link.")

    token_record.attempts += 1

    if token_record.expires_at < now:
        db.commit()
        raise HTTPException(status_code=400, detail="Verification link has expired. Please request a new verification email.")

    token_record.used_at = now

    user = db.query(User).filter(User.id == token_record.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Associated user account not found.")

    user.is_verified = True
    user.last_seen_at = now
    db.commit()

    request.session.clear()
    request.session["user_pk"] = user.id

    display_name = user.name or derive_display_name(user.email, user.name)
    return {
        "success": True,
        "message": "Email verified successfully.",
        "authenticated": True,
        "user": {
            "id": user.id,
            "email": user.email,
            "name": user.name or display_name,
            "display_name": display_name,
            "login": user.github_login,
            "avatar_url": user.avatar_url,
            "html_url": user.html_url,
            "github_user_id": user.github_user_id,
            "github_login": user.github_login,
            "is_verified": user.is_verified,
        },
        "github_connected": False,
        "github_user": None,
    }


@app.post("/api/auth/resend-verification")
def resend_verification(
    req: ResendVerificationRequest,
    db: Session = Depends(get_db),
):
    try:
        normalized_email = normalize_email(req.email)
    except ValueError:
        return {
            "success": True,
            "message": "If an unverified account exists with this email, a verification link has been sent.",
        }

    now = datetime.utcnow()
    user = db.query(User).filter(User.email == normalized_email).first()

    if not user or user.is_verified:
        return {
            "success": True,
            "message": "If an unverified account exists with this email, a verification link has been sent.",
        }

    recent_token = (
        db.query(EmailVerificationToken)
        .filter(
            EmailVerificationToken.user_id == user.id,
            EmailVerificationToken.token_type == "email_verification",
            EmailVerificationToken.created_at >= now - timedelta(seconds=60),
        )
        .first()
    )

    if recent_token:
        raise HTTPException(
            status_code=429,
            detail="Please wait at least 60 seconds before requesting another verification email.",
        )

    db.query(EmailVerificationToken).filter(
        EmailVerificationToken.user_id == user.id,
        EmailVerificationToken.token_type == "email_verification",
        EmailVerificationToken.used_at.is_(None),
    ).update({"used_at": now}, synchronize_session=False)

    raw_token, token_hash = generate_verification_token()
    token_expires_at = now + timedelta(minutes=15)

    new_token = EmailVerificationToken(
        user_id=user.id,
        token_hash=token_hash,
        token_type="email_verification",
        expires_at=token_expires_at,
        created_at=now,
    )
    db.add(new_token)

    email_result = send_verification_email(
        to_email=normalized_email,
        raw_token=raw_token,
        user_name=user.name,
    )

    if not email_result.get("success"):
        db.rollback()
        err_msg = email_result.get("error") or "Failed to deliver verification email."
        raise HTTPException(status_code=502, detail=f"Failed to resend verification email: {err_msg}")

    db.commit()

    return {
        "success": True,
        "message": "A fresh verification link has been sent to your email.",
        "email": mask_email(normalized_email),
    }


@app.get("/api/auth/me")
def auth_me(
    request: Request,
    db: Session = Depends(get_db),
):
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        try:
            decoded = verify_firebase_id_token(token)
            firebase_meta = decoded.get("firebase", {})
            sign_in_provider = firebase_meta.get("sign_in_provider", "password")
            is_verified = (
                True if sign_in_provider in ("google.com", "github.com")
                else decoded.get("email_verified", False)
            )
            user = upsert_firebase_user(db, decoded)
            display_name = user.name or decoded.get("name") or derive_display_name(user.email, user.name)
            return {
                "authenticated": True,
                "user": {
                    "id": user.id,
                    "firebase_uid": user.firebase_uid,
                    "email": user.email,
                    "name": user.name or display_name,
                    "display_name": display_name,
                    "login": user.github_login or (user.email.split('@')[0] if user.email else 'Rakshak User'),
                    "avatar_url": user.avatar_url or decoded.get("picture"),
                    "email_verified": is_verified,
                    "provider": sign_in_provider,
                },
            }
        except HTTPException:
            return {"authenticated": False, "user": None}

    user_pk = request.session.get("user_pk")

    if user_pk is not None:
        try:
            user = db.query(User).filter(User.id == int(user_pk)).first()
            if user and user.is_verified:
                github_access_token = request.session.get("github_access_token")
                has_github = bool(user.github_user_id and github_access_token)

                github_info = None
                if has_github:
                    github_info = {
                        "id": user.github_user_id,
                        "login": user.github_login,
                        "name": user.name,
                        "avatar_url": user.avatar_url,
                        "html_url": user.html_url,
                    }

                if not has_github:
                    # Clean session of any detached GitHub credentials
                    request.session.pop("github_access_token", None)
                    request.session.pop("github_user", None)

                display_name = user.name or derive_display_name(user.email, user.name)
                return {
                    "authenticated": True,
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "name": user.name or display_name,
                        "display_name": display_name,
                        "login": user.github_login if has_github else None,
                        "avatar_url": user.avatar_url if has_github else None,
                        "html_url": user.html_url if has_github else None,
                        "github_user_id": user.github_user_id,
                        "github_login": user.github_login,
                        "is_verified": user.is_verified,
                    },
                    "github_connected": has_github,
                    "github_user": github_info,
                }
        except (TypeError, ValueError):
            pass

    return {
        "authenticated": False,
        "user": None,
        "github_connected": False,
        "github_user": None,
    }


@app.post("/api/auth/logout")
def github_logout(request: Request):
    request.session.clear()

    return {
        "success": True,
        "message": "Logged out successfully",
    }


# ============================================================
# GITHUB REPOSITORIES
# ============================================================

@app.get("/api/github/repos")
def github_repositories(request: Request, current_user: User = Depends(get_current_user)):
    access_token = request.session.get(
        "github_access_token"
    )

    if not access_token or not current_user.github_user_id:
        raise HTTPException(
            status_code=401,
            detail="GitHub account is not connected. Please connect your GitHub account.",
        )

    url = (
        "https://api.github.com/user/repos"
        "?per_page=100"
        "&sort=updated"
        "&affiliation=owner,collaborator,organization_member"
    )

    github_request = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "Rakshak",
        },
    )

    try:
        with urllib.request.urlopen(
            github_request,
            timeout=30,
        ) as response:
            repositories = json.loads(
                response.read().decode()
            )

    except urllib.error.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail="GitHub repository request failed",
        )

    result = []

    for repo in repositories:
        result.append(
            {
                "id": repo.get("id"),
                "name": repo.get("name"),
                "full_name": repo.get("full_name"),
                "private": repo.get("private"),
                "description": repo.get("description"),
                "html_url": repo.get("html_url"),
                "clone_url": repo.get("clone_url"),
                "default_branch": repo.get("default_branch"),
                "language": repo.get("language"),
                "updated_at": repo.get("updated_at"),
                "owner": (
                    repo.get("owner", {}).get("login")
                ),
            }
        )

    return {
        "total": len(result),
        "repositories": result,
    }


# ============================================================
# GITHUB REPOSITORY INFORMATION
# ============================================================

@app.get("/api/github/repos/{owner}/{repo}")
def github_repository(
    request: Request,
    owner: str,
    repo: str,
):
    _validate_github_name(owner, "owner")
    _validate_github_name(repo, "repository")
    access_token = request.session.get(
        "github_access_token"
    )

    if not access_token:
        raise HTTPException(
            status_code=401,
            detail="GitHub authentication required",
        )

    try:
        repository = get_repository(
            access_token,
            owner,
            repo,
        )

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail="GitHub repository request failed",
        )

    return {
        "repository": {
            "id": repository.get("id"),
            "name": repository.get("name"),
            "full_name": repository.get("full_name"),
            "private": repository.get("private"),
            "description": repository.get("description"),
            "html_url": repository.get("html_url"),
            "default_branch": repository.get("default_branch"),
            "language": repository.get("language"),
            "owner": (
                repository.get("owner", {}).get("login")
            ),
        }
    }


# ============================================================
# LOCAL SCAN
# ============================================================

@app.post("/api/scan")
def scan_project(
    scan_request: ScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    target_path = scan_request.target_path

    if not os.path.exists(target_path):
        raise HTTPException(
            status_code=404,
            detail=f"Scan target not found: {target_path}",
        )

    scan_id = str(uuid.uuid4())

    scan = Scan(
        id=scan_id,
        target_path=target_path,
        event_type="local",
        status="running",
        code_scanning=scan_request.code_scanning,
        dependency_scanning=scan_request.dependency_scanning,
        secret_detection=scan_request.secret_detection,
        container_scanning=scan_request.container_scanning,
        total_findings=0,
        critical_count=0,
        high_count=0,
        medium_count=0,
        low_count=0,
        overall_risk=0,
        started_at=datetime.utcnow(),
        user_id=current_user.id,
    )

    db.add(scan)
    db.commit()

    all_findings = []

    try:
        # ----------------------------------------------------
        # CODE SCANNING
        # ----------------------------------------------------

        if scan_request.code_scanning:
            code_findings = run_code_scan(
                target_path
            )

            all_findings.extend((finding, "code") for finding in code_findings)

        # ----------------------------------------------------
        # DEPENDENCY SCANNING
        # ----------------------------------------------------

        if scan_request.dependency_scanning:
            dependency_findings = run_dependency_scan(
                target_path
            )

            all_findings.extend((finding, "dependency") for finding in dependency_findings)

        # ----------------------------------------------------
        # SECRET DETECTION
        # ----------------------------------------------------

        if scan_request.secret_detection:
            secret_findings = run_secret_scan(
                target_path
            )

            all_findings.extend((finding, "secret") for finding in secret_findings)

        # ----------------------------------------------------
        # CONTAINER SCANNING
        # ----------------------------------------------------

        if scan_request.container_scanning:

            if not scan_request.container_image:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "container_image is required "
                        "when container_scanning is enabled"
                    ),
                )

            container_findings = run_container_scan(
                scan_request.container_image
            )

            all_findings.extend((finding, "container") for finding in container_findings)

        # ----------------------------------------------------
        # SAVE FINDINGS
        # ----------------------------------------------------

        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        total_risk = 0

        finding_models = []
        for finding, scanner_type in all_findings:

            if hasattr(finding, "__dict__"):
                finding_data = finding.__dict__.copy()

            else:
                finding_data = dict(finding)

            # Remove SQLAlchemy internal field if present.
            finding_data.pop("_sa_instance_state", None)

            # ------------------------------------------------
            # AI / RULE-BASED ANALYSIS
            # ------------------------------------------------

            try:
                enriched = analyze_finding(
                    finding_data,
                    use_ai=False,
                )
            except TypeError:
                enriched = analyze_finding(
                    finding_data
                )

            severity = str(
                enriched.get(
                    "severity",
                    "low",
                )
            ).lower()

            if severity == "critical":
                critical_count += 1
            elif severity == "high":
                high_count += 1
            elif severity == "medium":
                medium_count += 1
            else:
                low_count += 1

            risk_score = float(
                enriched.get(
                    "risk_score",
                    0,
                )
                or 0
            )

            total_risk += risk_score

            finding_model = Finding(
                scan_id=scan_id,
                scanner_type=scanner_type,
                vulnerability_id=str(
                    enriched.get(
                        "vulnerability_id",
                        "",
                    )
                ),
                title=str(
                    enriched.get(
                        "title",
                        "",
                    )
                ),
                description=str(
                    enriched.get(
                        "description",
                        "",
                    )
                ),
                tool=str(
                    enriched.get(
                        "tool",
                        "",
                    )
                ),
                severity=severity,
                priority=str(
                    enriched.get(
                        "priority",
                        "",
                    )
                ),
                risk_score=risk_score,
                exploitability=float(
                    enriched.get(
                        "exploitability",
                        0,
                    )
                    or 0
                ),
                target=str(
                    enriched.get(
                        "target",
                        "",
                    )
                ),
                package_name=str(
                    enriched.get(
                        "package_name",
                        "",
                    )
                ),
                installed_version=str(
                    enriched.get(
                        "installed_version",
                        "",
                    )
                ),
                fixed_version=str(
                    enriched.get(
                        "fixed_version",
                        "",
                    )
                ),
                fix_available=bool(
                    enriched.get(
                        "fix_available",
                        False,
                    )
                ),
                production=bool(
                    enriched.get(
                        "production",
                        False,
                    )
                ),
                affected_packages=enriched.get(
                    "affected_packages"
                ),
                ai_explanation="",
                potential_impact="",
                recommended_action="",
                risk_summary="",
            )

            db.add(finding_model)
            finding_models.append(finding_model)

        # ----------------------------------------------------
        # RISK CALCULATION
        # ----------------------------------------------------

        total_findings = len(all_findings)

        if total_findings > 0:
            overall_risk = round(
                total_risk / total_findings,
                2,
            )
        else:
            overall_risk = 0

        # ----------------------------------------------------
        # COMPLETE SCAN
        # ----------------------------------------------------

        scan.status = "completed"
        scan.total_findings = total_findings
        scan.critical_count = critical_count
        scan.high_count = high_count
        scan.medium_count = medium_count
        scan.low_count = low_count
        scan.overall_risk = overall_risk
        scan.completed_at = datetime.utcnow()

        fixed_count = process_completed_scan_lifecycle(db, scan, finding_models)
        persist_security_gate(db, scan)
        create_scan_notifications(db, scan, finding_models, fixed_count=fixed_count)

        db.commit()

        return {
            "scan_id": scan_id,
            "status": "completed",
            "target_path": target_path,
            "total_findings": total_findings,
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "overall_risk": overall_risk,
            "code_scanning": scan_request.code_scanning,
            "dependency_scanning": scan_request.dependency_scanning,
            "secret_detection": scan_request.secret_detection,
            "container_scanning": scan_request.container_scanning,
        }

    except HTTPException:
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.completed_at = datetime.utcnow()
            create_scan_notifications(db, scan)
        db.commit()
        raise

    except Exception as exc:
        db.rollback()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            scan.status = "failed"
            scan.completed_at = datetime.utcnow()
            create_scan_notifications(db, scan)
        db.commit()

        raise HTTPException(
            status_code=500,
            detail=f"Scan failed: {str(exc)}",
        )


# ============================================================
# GITHUB REPOSITORY SCAN
# ============================================================

@app.post("/api/github/scan")
def scan_github_repository(
    scan_request: GitHubScanRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Manual GitHub repository scan — authenticated via OAuth session.

    Ownership is taken from the authenticated Rakshak workspace (never from
    the frontend). The repository/installation mapping used for later webhook
    ownership resolution is recorded best-effort after a successful scan.
    """
    access_token = request.session.get(
        "github_access_token"
    )

    if not access_token:
        raise HTTPException(
            status_code=401,
            detail="GitHub authentication required",
        )

    owner = scan_request.owner
    repo = scan_request.repo

    # Verify repository access and resolve default branch
    try:
        repository = get_repository(access_token, owner, repo)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    default_branch = repository.get("default_branch")
    ref = scan_request.ref or default_branch

    # Validate container_image before starting the scan
    if scan_request.container_scanning and not scan_request.container_image:
        raise HTTPException(
            status_code=400,
            detail="container_image is required when container_scanning is enabled",
        )

    try:
        scan_id = run_github_repository_scan(
            db=db,
            owner=owner,
            repo=repo,
            ref=ref,
            access_token=access_token,
            code_scanning=scan_request.code_scanning,
            dependency_scanning=scan_request.dependency_scanning,
            secret_detection=scan_request.secret_detection,
            container_scanning=scan_request.container_scanning,
            container_image=scan_request.container_image,
            trigger="manual",
            owner_user_id=current_user.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"GitHub repository scan failed: {str(exc)}",
        )

    # Best-effort: resolve the real GitHub App installation through GitHub and
    # record the workspace -> repository / installation mappings so later
    # webhook events can be safely attributed to this workspace.
    _link_manual_scan_workspace(db, current_user, owner, repo)

    # Retrieve completed scan for response
    scan = db.query(Scan).filter(Scan.id == scan_id).first()

    return {
        "scan_id": scan_id,
        "status": scan.status if scan else "completed",
        "repository": f"{owner}/{repo}",
        "ref": ref,
        "total_findings": scan.total_findings if scan else 0,
        "critical": scan.critical_count if scan else 0,
        "high": scan.high_count if scan else 0,
        "medium": scan.medium_count if scan else 0,
        "low": scan.low_count if scan else 0,
        "overall_risk": scan.overall_risk if scan else 0,
        "security_gate_status": scan.security_gate_status if scan else None,
        "security_gate_reason": scan.security_gate_reason if scan else None,
        "code_scanning": scan_request.code_scanning,
        "dependency_scanning": scan_request.dependency_scanning,
        "secret_detection": scan_request.secret_detection,
        "container_scanning": scan_request.container_scanning,
    }


# ============================================================
# SCAN HISTORY ENDPOINTS
# ============================================================

@app.get("/api/scans")
def get_scans(
    repository: str | None = None,
    status: str | None = None,
    event_type: str | None = None,
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve paginated scan history with optional filtering.

    Workspace-scoped: only scans owned by the authenticated user are returned.
    Historical/system records with NULL ownership are hidden.
    Ordered by newest scans first (started_at DESC).
    Safe parameterized filtering for repository, status, and event_type.
    """
    query = db.query(Scan).filter(Scan.user_id == current_user.id)

    if repository:
        # Match against either explicit repository column or target_path
        query = query.filter(
            or_(
                Scan.repository == repository,
                Scan.target_path == f"github.com/{repository}",
                Scan.target_path == repository,
            )
        )

    if status:
        query = query.filter(Scan.status == status)

    if event_type:
        query = query.filter(Scan.event_type == event_type)

    total = query.count()
    scans = (
        query.order_by(Scan.started_at.desc(), Scan.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    items = []
    for s in scans:
        resolved_repo = s.repository
        if not resolved_repo and s.target_path.startswith("github.com/"):
            resolved_repo = s.target_path[len("github.com/"):]

        items.append(
            {
                "scan_id": s.id,
                "repository": resolved_repo,
                "target_path": s.target_path,
                "status": s.status,
                "event_type": s.event_type or "unknown",
                "ref": s.ref,
                "commit_sha": s.commit_sha,
                "total_findings": s.total_findings,
                "critical": s.critical_count,
                "high": s.high_count,
                "medium": s.medium_count,
                "low": s.low_count,
                "risk_score": s.overall_risk,
                "started_at": s.started_at.isoformat() if s.started_at else None,
                "completed_at": s.completed_at.isoformat() if s.completed_at else None,
                "security_gate_status": s.security_gate_status,
                "security_gate_reason": s.security_gate_reason,
            }
        )

    return {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/scans/{scan_id}")
def get_scan_by_id(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve detailed metadata and findings for a specific scan.

    Ownership is enforced inside the query: another workspace's scan (or an
    unowned historical scan) is indistinguishable from a missing scan (404).
    """
    scan = (
        db.query(Scan)
        .filter(
            Scan.id == scan_id,
            Scan.user_id == current_user.id,
        )
        .first()
    )

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    resolved_repo = scan.repository
    if not resolved_repo and scan.target_path.startswith("github.com/"):
        resolved_repo = scan.target_path[len("github.com/"):]

    return {
        "scan_id": scan.id,
        "repository": resolved_repo,
        "target_path": scan.target_path,
        "status": scan.status,
        "event_type": scan.event_type or "unknown",
        "ref": scan.ref,
        "commit_sha": scan.commit_sha,
        "total_findings": scan.total_findings,
        "critical": scan.critical_count,
        "high": scan.high_count,
        "medium": scan.medium_count,
        "low": scan.low_count,
        "overall_risk": scan.overall_risk,
        "code_scanning": scan.code_scanning,
        "dependency_scanning": scan.dependency_scanning,
        "secret_detection": scan.secret_detection,
        "container_scanning": scan.container_scanning,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "security_gate_status": scan.security_gate_status,
        "security_gate_reason": scan.security_gate_reason,
        "findings": [
            {
                "id": f.id,
                "scan_id": f.scan_id,
                "vulnerability_id": f.vulnerability_id,
                "title": f.title,
                "description": f.description,
                "tool": f.tool,
                "severity": f.severity,
                "priority": f.priority,
                "risk_score": f.risk_score,
                "exploitability": f.exploitability,
                "target": f.target,
                "package_name": f.package_name,
                "installed_version": f.installed_version,
                "fixed_version": f.fixed_version,
                "fix_available": f.fix_available,
                "production": f.production,
                "affected_packages": f.affected_packages,
                "ai_explanation": f.ai_explanation,
                "potential_impact": f.potential_impact,
                "recommended_action": f.recommended_action,
                "risk_summary": f.risk_summary,
                "finding_key": f.finding_key,
                "scanner_type": f.scanner_type,
                "lifecycle_status": f.lifecycle_status,
                "first_seen_at": f.first_seen_at.isoformat() if f.first_seen_at else None,
                "last_seen_at": f.last_seen_at.isoformat() if f.last_seen_at else None,
                "fixed_at": f.fixed_at.isoformat() if f.fixed_at else None,
                "reopened_at": f.reopened_at.isoformat() if f.reopened_at else None,
                "occurrence_count": f.occurrence_count,
            }
            for f in scan.findings
        ],
    }


@app.get("/api/scans/{scan_id}/security-gate")
def get_security_gate(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = (
        db.query(Scan)
        .filter(
            Scan.id == scan_id,
            Scan.user_id == current_user.id,
        )
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    status = scan.security_gate_status
    reason = scan.security_gate_reason
    if not status:
        status = "ERROR" if scan.status != "completed" else "UNKNOWN"
        reason = reason or "No persisted security gate result is available for this scan."

    return {
        "scan_id": scan.id,
        "status": status,
        "reason": reason,
        "critical_count": scan.critical_count,
        "high_count": scan.high_count,
        "medium_count": scan.medium_count,
        "low_count": scan.low_count,
        "total_findings": scan.total_findings,
    }


# ============================================================
# SUMMARY
# ============================================================

@app.get("/api/summary")
def get_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    latest_scan = (
        db.query(Scan)
        .filter(Scan.user_id == current_user.id)
        .order_by(
            Scan.started_at.desc()
        )
        .first()
    )

    if not latest_scan:
        return {
            "security_health_score": 100,
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "overall_risk": 0,
            "ai_remediations": 0,
            "new_findings": 0,
            "open_findings": 0,
            "fixed_findings": 0,
            "reopened_findings": 0,
        }

    ai_remediations = (
        db.query(Finding)
        .filter(
            Finding.scan_id == latest_scan.id,
            Finding.ai_explanation != "",
        )
        .count()
    )

    # Workspace-scoped lifecycle counts: derived from findings belonging to
    # scans OWNED by the authenticated workspace. Counting DISTINCT
    # finding_key deduplicates the same logical finding repeated across
    # multiple scans. Global FindingLifecycle rows are never exposed.
    lifecycle_rows = (
        db.query(
            Finding.lifecycle_status,
            func.count(distinct(Finding.finding_key)),
        )
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.user_id == current_user.id)
        .group_by(Finding.lifecycle_status)
        .all()
    )

    lifecycle_counts = {status: 0 for status in ("new", "open", "fixed", "reopened")}
    for lifecycle_status_value, key_count in lifecycle_rows:
        if lifecycle_status_value in lifecycle_counts:
            lifecycle_counts[lifecycle_status_value] = int(key_count or 0)

    health_score = max(
        0,
        round(
            100 - latest_scan.overall_risk
        ),
    )

    return {
        "security_health_score": health_score,
        "total_findings": latest_scan.total_findings,
        "critical": latest_scan.critical_count,
        "high": latest_scan.high_count,
        "medium": latest_scan.medium_count,
        "low": latest_scan.low_count,
        "overall_risk": latest_scan.overall_risk,
        "ai_remediations": ai_remediations,
        "scan_id": latest_scan.id,
        "status": latest_scan.status,
        "new_findings": lifecycle_counts["new"],
        "open_findings": lifecycle_counts["open"],
        "fixed_findings": lifecycle_counts["fixed"],
        "reopened_findings": lifecycle_counts["reopened"],
    }


# ============================================================
# FINDINGS
# ============================================================

@app.get("/api/findings")
def get_findings(
    lifecycle_status: str | None = Query(default=None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Workspace-scoped findings: only findings belonging to scans owned by
    the authenticated user. Unowned historical findings are hidden."""
    query = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(Scan.user_id == current_user.id)
    )
    if lifecycle_status:
        lifecycle_status = lifecycle_status.lower()
        if lifecycle_status not in {"new", "open", "fixed", "reopened"}:
            raise HTTPException(status_code=422, detail="Invalid lifecycle_status")
        query = query.filter(Finding.lifecycle_status == lifecycle_status)

    findings = (
        query
        .order_by(
            Finding.id.desc()
        )
        .all()
    )

    return [
        {
            "id": finding.id,
            "scan_id": finding.scan_id,
            "vulnerability_id": finding.vulnerability_id,
            "title": finding.title,
            "description": finding.description,
            "tool": finding.tool,
            "severity": finding.severity,
            "priority": finding.priority,
            "risk_score": finding.risk_score,
            "exploitability": finding.exploitability,
            "target": finding.target,
            "package_name": finding.package_name,
            "installed_version": finding.installed_version,
            "fixed_version": finding.fixed_version,
            "fix_available": finding.fix_available,
            "production": finding.production,
            "affected_packages": finding.affected_packages,
            "ai_explanation": finding.ai_explanation,
            "potential_impact": finding.potential_impact,
            "recommended_action": finding.recommended_action,
            "risk_summary": finding.risk_summary,
            "finding_key": finding.finding_key,
            "scanner_type": finding.scanner_type,
            "lifecycle_status": finding.lifecycle_status,
            "first_seen_at": finding.first_seen_at.isoformat() if finding.first_seen_at else None,
            "last_seen_at": finding.last_seen_at.isoformat() if finding.last_seen_at else None,
            "fixed_at": finding.fixed_at.isoformat() if finding.fixed_at else None,
            "reopened_at": finding.reopened_at.isoformat() if finding.reopened_at else None,
            "occurrence_count": finding.occurrence_count,
        }
        for finding in findings
    ]


# ============================================================
# SINGLE FINDING
# ============================================================

@app.get("/api/findings/{vulnerability_id}")
def get_finding(
    vulnerability_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Single finding lookup — ownership enforced inside the query via the
    Finding → Scan join. Other workspaces' findings resolve to 404."""
    finding = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(
            Finding.vulnerability_id
            == vulnerability_id,
            Scan.user_id == current_user.id,
        )
        .order_by(
            Finding.id.desc()
        )
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "vulnerability_id": finding.vulnerability_id,
        "title": finding.title,
        "description": finding.description,
        "tool": finding.tool,
        "severity": finding.severity,
        "priority": finding.priority,
        "risk_score": finding.risk_score,
        "exploitability": finding.exploitability,
        "target": finding.target,
        "scanner_type": finding.scanner_type,
        "finding_key": finding.finding_key,
        "package_name": finding.package_name,
        "installed_version": finding.installed_version,
        "fixed_version": finding.fixed_version,
        "fix_available": finding.fix_available,
        "production": finding.production,
        "affected_packages": finding.affected_packages,
        "file_path": getattr(finding, "file_path", ""),
        "line_number": getattr(finding, "line_number", ""),
        "evidence": getattr(finding, "evidence", ""),
        "code_snippet": getattr(finding, "code_snippet", ""),
        "ai_explanation": finding.ai_explanation,
        "potential_impact": finding.potential_impact,
        "recommended_action": finding.recommended_action,
        "risk_summary": finding.risk_summary,
        "finding_key": finding.finding_key,
        "scanner_type": finding.scanner_type,
        "lifecycle_status": finding.lifecycle_status,
        "first_seen_at": finding.first_seen_at.isoformat() if finding.first_seen_at else None,
        "last_seen_at": finding.last_seen_at.isoformat() if finding.last_seen_at else None,
        "fixed_at": finding.fixed_at.isoformat() if finding.fixed_at else None,
        "reopened_at": finding.reopened_at.isoformat() if finding.reopened_at else None,
        "occurrence_count": finding.occurrence_count,
    }


# ============================================================
# AI ANALYSIS
# ============================================================

@app.post("/api/findings/{vulnerability_id}/analyze")
def analyze_single_finding(
    vulnerability_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """AI analysis for a single finding — ownership enforced inside the query
    via the Finding → Scan join; AI enrichment can never mutate another
    workspace's finding."""
    finding = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(
            Finding.vulnerability_id
            == vulnerability_id,
            Scan.user_id == current_user.id,
        )
        .order_by(
            Finding.id.desc()
        )
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=404,
            detail="Finding not found",
        )

    finding_data = {
        "vulnerability_id": finding.vulnerability_id,
        "title": finding.title,
        "description": finding.description,
        "tool": finding.tool,
        "severity": finding.severity,
        "priority": finding.priority,
        "risk_score": finding.risk_score,
        "exploitability": finding.exploitability,
        "target": finding.target,
        "scanner_type": finding.scanner_type,
        "finding_key": finding.finding_key,
        "package_name": finding.package_name,
        "installed_version": finding.installed_version,
        "fixed_version": finding.fixed_version,
        "fix_available": finding.fix_available,
        "production": finding.production,
        "affected_packages": finding.affected_packages,
        "evidence": finding.description,
        "file_path": finding.target,
    }

    try:
        enriched = analyze_finding(
            finding_data,
            use_ai=True,
        )
    except TypeError:
        enriched = analyze_finding(
            finding_data
        )

    finding.ai_explanation = str(
        enriched.get(
            "ai_explanation",
            "",
        )
    )

    finding.potential_impact = str(
        enriched.get(
            "potential_impact",
            "",
        )
    )

    finding.recommended_action = str(
        enriched.get(
            "recommended_action",
            "",
        )
    )

    finding.risk_summary = str(
        enriched.get(
            "risk_summary",
            "",
        )
    )

    db.commit()
    db.refresh(finding)

    return {
        "vulnerability_id": finding.vulnerability_id,
        "ai_explanation": finding.ai_explanation,
        "potential_impact": finding.potential_impact,
        "recommended_action": finding.recommended_action,
        "risk_summary": finding.risk_summary,
    }




# ============================================================
# NOTIFICATIONS API (WORKSPACE-SCOPED)
# ============================================================


@app.get("/api/notifications")
def list_notifications(
    limit: int = Query(default=50, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Retrieve workspace notifications for the authenticated user, newest first."""
    notifications = (
        db.query(Notification)
        .filter(Notification.user_id == current_user.id)
        .order_by(Notification.created_at.desc(), Notification.id.desc())
        .limit(limit)
        .all()
    )

    # If new user workspace has zero notifications, seed an initial real telemetry alert
    if not notifications and db.query(Notification).filter(Notification.user_id == current_user.id).count() == 0:
        welcome_notif = Notification(
            user_id=current_user.id,
            notification_type="security_telemetry",
            title="DevSecOps Defense Grid Online",
            message="Rakshak real-time AST parser and automated threat prioritization are active for your workspace.",
            severity="medium",
            is_read=False,
            created_at=datetime.utcnow(),
        )
        db.add(welcome_notif)
        db.commit()
        db.refresh(welcome_notif)
        notifications = [welcome_notif]

    unread_count = (
        db.query(Notification)
        .filter(
            Notification.user_id == current_user.id,
            Notification.is_read.is_(False),
        )
        .count()
    )

    return {
        "notifications": [
            {
                "id": n.id,
                "user_id": n.user_id,
                "scan_id": n.scan_id,
                "finding_id": n.finding_id,
                "notification_type": n.notification_type,
                "title": n.title,
                "message": n.message,
                "severity": n.severity,
                "is_read": n.is_read,
                "created_at": n.created_at.isoformat() if n.created_at else None,
            }
            for n in notifications
        ],
        "unread_count": unread_count,
    }


@app.post("/api/notifications/{notification_id}/read")
def mark_notification_read(
    notification_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Mark a single workspace notification as read."""
    notif = (
        db.query(Notification)
        .filter(
            Notification.id == notification_id,
            Notification.user_id == current_user.id,
        )
        .first()
    )

    if not notif:
        raise HTTPException(status_code=404, detail="Notification not found")

    notif.is_read = True
    db.commit()

    unread_count = (
        db.query(Notification)
        .filter(
            Notification.user_id == current_user.id,
            Notification.is_read.is_(False),
        )
        .count()
    )

    return {
        "status": "success",
        "notification_id": notif.id,
        "is_read": True,
        "unread_count": unread_count,
    }


@app.post("/api/notifications/read-all")
def mark_all_notifications_read(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Mark all unread workspace notifications as read for the current user."""
    db.query(Notification).filter(
        Notification.user_id == current_user.id,
        Notification.is_read.is_(False),
    ).update({"is_read": True}, synchronize_session=False)
    db.commit()

    return {
        "status": "success",
        "message": "All notifications marked as read",
        "unread_count": 0,
    }


# ============================================================
# GITHUB WEBHOOK
# ============================================================

# PR actions that should trigger an automatic scan
_SCAN_PR_ACTIONS = frozenset({"opened", "synchronize", "reopened"})


@app.post("/api/github/webhook")
async def github_webhook(
    request: Request,
    db: Session = Depends(get_db),
):
    """Receive, verify, and enqueue automatic scanning for GitHub webhook events.

    Phase 6 — Durable Webhook Deduplication:
    - HMAC-SHA256 signature verified first on raw request bytes.
    - JSON parsed only after HMAC verification.
    - Delivery-ID persisted atomically to PostgreSQL with unique constraint.
    - Duplicate delivery IDs cleanly rejected (no scan task enqueued).
    - Valid branch push and PR opened/synchronize/reopened events queue scan.
    - Delivery lifecycle: received -> queued -> running -> completed / failed / ignored.
    """
    global _processed_deliveries

    # --- 1. Read raw bytes BEFORE any JSON parsing ---
    raw_body = await request.body()

    # --- 2. Extract GitHub headers ---
    event_type = request.headers.get("X-GitHub-Event", "")
    signature_header = request.headers.get("X-Hub-Signature-256")
    delivery_id = request.headers.get("X-GitHub-Delivery")

    # --- 3. Verify HMAC-SHA256 signature ---
    try:
        webhook_secret = get_webhook_secret()
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    if not verify_github_signature(raw_body, signature_header, secret=webhook_secret):
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing webhook signature. "
                   "Ensure GITHUB_WEBHOOK_SECRET matches the secret configured in GitHub.",
        )

    # --- 4. Parse JSON (only AFTER signature verification) ---
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Webhook payload is not valid JSON.",
        )

    # --- 5. ping event ---
    if event_type == "ping":
        return {
            "status": "ok",
            "event": "ping",
            "zen": payload.get("zen", ""),
            "hook_id": payload.get("hook_id"),
        }

    # --- 6. Handle unsupported events ---
    if event_type not in ("push", "pull_request"):
        if delivery_id:
            delivery = GitHubWebhookDelivery(
                delivery_id=delivery_id,
                event_type=event_type or "unknown",
                action=payload.get("action") if isinstance(payload, dict) else None,
                repository=payload.get("repository", {}).get("full_name") if isinstance(payload, dict) else None,
                owner=payload.get("repository", {}).get("owner", {}).get("login") if isinstance(payload, dict) else None,
                status="ignored",
                received_at=datetime.utcnow(),
            )
            try:
                db.add(delivery)
                db.commit()
                _processed_deliveries.add(delivery_id)
            except IntegrityError:
                db.rollback()
                _processed_deliveries.add(delivery_id)
                return JSONResponse(
                    status_code=200,
                    content={
                        "status": "duplicate",
                        "event": event_type,
                        "delivery_id": delivery_id,
                        "detail": "Delivery already processed.",
                    },
                )
            except Exception as db_exc:
                db.rollback()
                logger.error("[Webhook] Database error recording unsupported delivery %s: %s", delivery_id, str(db_exc))
                raise HTTPException(status_code=503, detail="Database temporarily unavailable.")

        return {
            "status": "ignored",
            "event": event_type or "unknown",
            "detail": "Event type is not handled in this phase.",
        }

    # --- 7. Extract metadata ---
    if event_type == "push":
        metadata = extract_push_event_metadata(payload, delivery_id)
        log_webhook_event("push", metadata)
        action = None
        ref = metadata.get("ref", "")
        commit_sha = metadata.get("after")
    else:  # pull_request
        metadata = extract_pull_request_event_metadata(payload, delivery_id)
        log_webhook_event("pull_request", metadata)
        action = metadata.get("action", "")
        ref = metadata.get("head_branch", "")
        commit_sha = metadata.get("head_sha")

    owner = metadata.get("owner")
    repo = metadata.get("repository_name")
    installation_id = metadata.get("installation_id")
    repo_full_name = metadata.get("repository_full_name")

    if not owner or not repo:
        raise HTTPException(status_code=400, detail="Webhook repository metadata is invalid")
    _validate_github_name(owner, "owner")
    _validate_github_name(repo, "repository")
    _validate_untrusted_ref(ref)
    if commit_sha and (len(commit_sha) > 100 or any(char in commit_sha for char in "\r\n\x00")):
        raise HTTPException(status_code=400, detail="Webhook commit metadata is invalid")

    # --- 8. Atomic delivery persistence & deduplication ---
    delivery = None
    if delivery_id:
        delivery = GitHubWebhookDelivery(
            delivery_id=delivery_id,
            event_type=event_type,
            action=action,
            repository=repo_full_name,
            owner=owner,
            ref=ref,
            commit_sha=commit_sha,
            status="received",
            received_at=datetime.utcnow(),
            installation_id=installation_id,
        )
        try:
            db.add(delivery)
            db.commit()
            db.refresh(delivery)
            _processed_deliveries.add(delivery_id)
        except IntegrityError:
            db.rollback()
            _processed_deliveries.add(delivery_id)
            logger.info("[Webhook] Duplicate delivery_id ignored: %s", delivery_id)
            return JSONResponse(
                status_code=200,
                content={
                    "status": "duplicate",
                    "event": event_type,
                    "delivery_id": delivery_id,
                    "detail": "Delivery already processed.",
                },
            )
        except Exception as db_exc:
            db.rollback()
            logger.error("[Webhook] Database error during delivery deduplication: %s", str(db_exc))
            raise HTTPException(
                status_code=503,
                detail="Database temporarily unavailable.",
            )

    # --- 9. Resolve owning workspace (safe webhook-to-workspace association) ---
    # Only enqueue a scan when ownership can be safely established via the
    # GitHub App installation mapping (or an unambiguous repository mapping).
    # The GitHub repository owner's login is NEVER used as a Rakshak identity,
    # and ownerless scans are never created from webhook events.
    owner_user_id = _resolve_webhook_workspace(db, installation_id, repo_full_name)

    if owner_user_id is None:
        logger.info(
            "[Webhook] No Rakshak workspace associated with repository=%s installation=%s — delivery ignored: %s",
            repo_full_name,
            installation_id,
            delivery_id,
        )
        if delivery:
            delivery.status = "ignored"
            delivery.error_message = (
                "No Rakshak workspace is associated with this repository/installation; "
                "scan not enqueued."
            )
            db.commit()
        return JSONResponse(
            status_code=200,
            content={
                "status": "ignored",
                "event": event_type,
                "delivery_id": delivery_id,
                "repository": repo_full_name,
                "detail": (
                    "Repository is not associated with a Rakshak workspace; "
                    "scan skipped."
                ),
                "scan_queued": False,
                "task_id": None,
            },
        )

    # --- 10. Evaluate actionable scan ---
    scan_queued = False
    task_id = None

    if event_type == "push":
        if owner and repo and ref and ref.startswith("refs/heads/"):
            scan_ref = commit_sha or ref
            if delivery:
                delivery.status = "queued"
                db.commit()
            try:
                task = run_github_repository_scan_task.delay(
                    owner=owner,
                    repo=repo,
                    ref=scan_ref,
                    access_token=None,
                    code_scanning=True,
                    dependency_scanning=True,
                    secret_detection=True,
                    container_scanning=False,
                    container_image=None,
                    trigger="push",
                    delivery_id=delivery_id,
                    installation_id=installation_id,
                    owner_user_id=owner_user_id,
                )
                task_id = getattr(task, "id", None)
                scan_queued = True
            except Exception as queue_exc:
                logger.error("[Webhook] Failed to enqueue push scan task: %s", str(queue_exc))
                if delivery:
                    delivery.status = "failed"
                    delivery.error_message = f"Queue error: {str(queue_exc)}"
                    db.commit()
                raise HTTPException(
                    status_code=503,
                    detail="Scan task queue is temporarily unavailable.",
                )
        else:
            if delivery:
                delivery.status = "ignored"
                db.commit()

        response_content = {
            "status": "accepted",
            "event": "push",
            "delivery_id": delivery_id,
            "repository": repo_full_name,
            "ref": ref,
            "commits": metadata.get("commits_count"),
            "scan_queued": scan_queued,
            "task_id": task_id,
        }
        status_code = 202 if scan_queued else 200
        return JSONResponse(status_code=status_code, content=response_content)

    elif event_type == "pull_request":
        pr_number = metadata.get("pr_number")
        if action in _SCAN_PR_ACTIONS and owner and repo:
            head_sha = metadata.get("head_sha")
            scan_ref = head_sha or metadata.get("head_branch")
            check_token = get_check_run_token(None)

            if delivery:
                delivery.status = "queued"
                db.commit()

            try:
                task = run_github_repository_scan_task.delay(
                    owner=owner,
                    repo=repo,
                    ref=scan_ref,
                    access_token=None,
                    code_scanning=True,
                    dependency_scanning=True,
                    secret_detection=True,
                    container_scanning=False,
                    container_image=None,
                    trigger="pull_request",
                    delivery_id=delivery_id,
                    pr_head_sha=head_sha,
                    check_run_access_token=check_token,
                    installation_id=installation_id,
                    owner_user_id=owner_user_id,
                )
                task_id = getattr(task, "id", None)
                scan_queued = True
            except Exception as queue_exc:
                logger.error("[Webhook] Failed to enqueue PR scan task: %s", str(queue_exc))
                if delivery:
                    delivery.status = "failed"
                    delivery.error_message = f"Queue error: {str(queue_exc)}"
                    db.commit()
                raise HTTPException(
                    status_code=503,
                    detail="Scan task queue is temporarily unavailable.",
                )
        else:
            if delivery:
                delivery.status = "ignored"
                db.commit()

        response_content = {
            "status": "accepted",
            "event": "pull_request",
            "delivery_id": delivery_id,
            "repository": repo_full_name,
            "pr_number": pr_number,
            "action": action,
            "scan_queued": scan_queued,
            "task_id": task_id,
        }
        status_code = 202 if scan_queued else 200
        return JSONResponse(status_code=status_code, content=response_content)


# ============================================================
# GITHUB APP ENDPOINTS
# ============================================================


@app.get("/api/github/app/status")
def github_app_status():
    """Return safe configuration status of the GitHub App integration.

    Never exposes private keys, JWTs, or installation access tokens.
    """
    return get_github_app_status()


# ============================================================
# TASK QUEUE SYSTEM ENDPOINTS
# ============================================================


@app.get("/api/system/queue-status")
def system_queue_status():
    """Return safe operational status of the Celery/Redis task queue.

    Never exposes Redis passwords, internal hostnames, or connection strings.
    """
    return get_queue_status()


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", "8000"))
    host = os.getenv("HOST", "0.0.0.0")
    uvicorn.run("app.main:app", host=host, port=port)
