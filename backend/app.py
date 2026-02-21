from fastapi import FastAPI, Depends, HTTPException, Query, Request, UploadFile, File, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import func, text
import uuid
from fastapi.openapi.utils import get_openapi
from jose import jwt, JWTError
from datetime import datetime, timezone
import logging
from dotenv import load_dotenv, find_dotenv
from pydantic import BaseModel
from typing import Optional
import os
import json
from pathlib import Path
import shutil
from PIL import Image, ImageDraw, ImageFont
import io

# Load environment variables
env_path = Path(__file__).parent / ".env"
env_candidates = [env_path]
found_env = find_dotenv(".env", usecwd=True)
if found_env:
    env_candidates.append(Path(found_env))

_loaded_env_paths: list[str] = []
for candidate in env_candidates:
    if candidate and Path(candidate).exists():
        load_dotenv(dotenv_path=candidate, override=True)
        _loaded_env_paths.append(str(candidate))

logger = logging.getLogger("backend")


def _require_env_var(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value


# Fail fast if Microsoft OAuth is not configured
_require_env_var("MICROSOFT_CLIENT_ID")
_require_env_var("MICROSOFT_TENANT_ID")


# Create avatars directory if it doesn't exist
AVATARS_DIR = Path(__file__).parent / "avatars"
AVATARS_DIR.mkdir(exist_ok=True)

# Internal imports
from database import Base, engine, SessionLocal
import models
from schemas import (
    UserCreate, UserLogin, LogCreate, LogResponse, TokenResponse, UserResponse,
    EnhancedTokenResponse, SessionResponse, EnhancedLogResponse,
    AdminUsersResponse, AdminUserLogsResponse, AdminSessionsResponse, AdminUserOut,
    LockUnlockRequestCreate, LockUnlockRequestResponse, ReviewRequestAction, PendingRequestsResponse,
    DeviceRegister, DeviceResponse,
    AgentRegisterRequest, AgentRegisterResponse, AgentHeartbeatRequest, AgentHeartbeatResponse,
    TelemetryResponse, TelemetryMetrics, AgentTokenRotateRequest, AgentTokenRotateResponse,
    AgentApprovalRequest, AgentApprovalResponse
)
from utils import (
    get_client_ip, get_user_agent_info, get_location_from_ip,
    get_location_string, calculate_login_risk_score, get_risk_status,
    update_login_ip_history, hash_agent_token, verify_agent_token,
    calculate_agent_trust_score, generate_agent_token, validate_agent_token_rotation,
    revoke_device_sessions
)
from rate_limit import check_rate_limit_ip, check_rate_limit_token
from auth import hash_password, verify_password, create_access_token, create_refresh_token, SECRET_KEY, ALGORITHM
from dependencies import get_current_user, admin_required
from models import Log, User, Device, Telemetry
from google_oauth import verify_google_token, get_or_create_google_user
from microsoft_oauth import verify_microsoft_token, get_or_create_microsoft_user


# Custom JSON encoder to handle timezone-aware datetimes
class CustomJSONResponse(JSONResponse):
    def render(self, content) -> bytes:
        return json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=None,
            separators=(",", ":"),
            default=self.json_encoder
        ).encode("utf-8")
    
    @staticmethod
    def json_encoder(obj):
        """Convert datetime objects to ISO format with UTC timezone"""
        if isinstance(obj, datetime):
            # If datetime is naive, assume it's UTC and make it aware
            if obj.tzinfo is None:
                obj = obj.replace(tzinfo=timezone.utc)
            # Return ISO format with timezone (e.g., 2026-02-20T14:20:00+00:00)
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")


app = FastAPI(
    title="Secure Access API", 
    version="1.0", 
    description="Zero Trust Monitoring System Backend",
    default_response_class=CustomJSONResponse
)


@app.on_event("startup")
def _startup_env_check() -> None:
    client_id = os.getenv("MICROSOFT_CLIENT_ID")
    tenant_id = os.getenv("MICROSOFT_TENANT_ID")
    logger.info(
        "Startup env check microsoft_client_id=%s microsoft_tenant_id=%s env_paths=%s",
        bool(client_id),
        tenant_id,
        _loaded_env_paths or "(no .env found)",
    )
    if not client_id or not tenant_id:
        raise RuntimeError(
            "Missing MICROSOFT_CLIENT_ID or MICROSOFT_TENANT_ID. "
            f"Checked: {_loaded_env_paths or '(no .env found)'}"
        )


def is_superadmin(user) -> bool:
    return user and user.role == "superadmin"


def parse_iso_datetime(value: str | None):
    if not value:
        return None
    try:
        cleaned = value.replace("Z", "+00:00")
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return None


def build_pagination(total: int, page: int, limit: int):
    total_pages = (total + limit - 1) // limit if limit else 1
    return {
        "total": total,
        "page": page,
        "limit": limit,
        "total_pages": total_pages
    }

# ---------------- CORS SETTINGS ----------------
cors_origins = [origin.strip() for origin in os.getenv(
    "CORS_ORIGINS",
    "http://localhost:5174,http://localhost:5173,http://127.0.0.1:5173,http://127.0.0.1:5174"
).split(",")]
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create DB tables
Base.metadata.create_all(bind=engine)


def _ensure_sqlite_oauth_schema() -> None:
    """Best-effort SQLite compatibility patch for existing dev databases."""
    try:
        with engine.begin() as conn:
            result = conn.execute(text("PRAGMA table_info(users)"))
            columns = {row[1] for row in result.fetchall()}

            if "auth_provider" not in columns:
                conn.execute(
                    text("ALTER TABLE users ADD COLUMN auth_provider VARCHAR NOT NULL DEFAULT 'local'")
                )
                logger.warning("Added missing users.auth_provider column")

            if "microsoft_id" not in columns:
                conn.execute(text("ALTER TABLE users ADD COLUMN microsoft_id VARCHAR"))
                logger.warning("Added missing users.microsoft_id column")

            conn.execute(text("CREATE INDEX IF NOT EXISTS ix_users_auth_provider ON users (auth_provider)"))
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_microsoft_id ON users (microsoft_id)"))
    except Exception as exc:
        logger.warning("SQLite schema compatibility check skipped: %s", str(exc))


_ensure_sqlite_oauth_schema()

# Mount avatars directory for serving user photos
app.mount("/avatars", StaticFiles(directory=str(AVATARS_DIR)), name="avatars")

# DB Session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

# Helper function to generate default avatar with initials
def generate_default_avatar(name: str, user_id: int) -> str:
    """Generate a colorful avatar with user initials"""
    try:
        # Get initials from name
        initials = "".join([word[0].upper() for word in name.split() if word])[:2]
        if not initials:
            initials = "U"
        
        # Color palette for avatars
        colors = [
            "#FF6B6B", "#4ECDC4", "#45B7D1", "#FFA07A", "#98D8C8",
            "#F7DC6F", "#BB8FCE", "#85C1E2", "#F8B88B", "#90EE90"
        ]
        color = colors[user_id % len(colors)]
        
        # Create image
        size = 200
        img = Image.new("RGB", (size, size), color=color)
        draw = ImageDraw.Draw(img)
        
        # Draw initials
        try:
            # Try to use a nice font if available
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if os.name != 'nt' 
                                     else "C:\\Windows\\Fonts\\ariblk.ttf", 80)
        except:
            font = ImageFont.load_default()
        
        # Center text
        bbox = draw.textbbox((0, 0), initials, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        x = (size - text_width) // 2
        y = (size - text_height) // 2
        
        draw.text((x, y), initials, fill="white", font=font)
        
        # Save avatar
        avatar_filename = f"avatar_{user_id}_{int(datetime.now(timezone.utc).timestamp())}.png"
        avatar_path = AVATARS_DIR / avatar_filename
        img.save(avatar_path)
        
        return f"/avatars/{avatar_filename}"
    except Exception as e:
        print(f"Avatar generation error: {str(e)}")
        return None

# Helper function to save uploaded photo
async def save_user_photo(file: UploadFile, user_id: int) -> str:
    """Save uploaded photo and return the path"""
    try:
        # Create unique filename
        file_ext = file.filename.split(".")[-1] if file.filename else "jpg"
        file_ext = file_ext.lower()
        if file_ext not in ["jpg", "jpeg", "png", "gif"]:
            file_ext = "jpg"
        
        filename = f"photo_{user_id}_{int(datetime.now(timezone.utc).timestamp())}.{file_ext}"
        filepath = AVATARS_DIR / filename
        
        # Read and validate image
        contents = await file.read()
        try:
            img = Image.open(io.BytesIO(contents))
            # Resize if too large
            if img.size[0] > 500 or img.size[1] > 500:
                img.thumbnail((500, 500), Image.Resampling.LANCZOS)
            img.save(filepath)
        except:
            raise HTTPException(status_code=400, detail="Invalid image file")
        
        return f"/avatars/{filename}"
    except Exception as e:
        print(f"Photo save error: {str(e)}")
        return None

# Helper function to get user_id from username
def get_user_id_by_username(username: str, db: Session) -> int:
    """Resolve username to user_id"""
    user = db.query(models.User).filter(models.User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user.id

# Helper class for registration with file support
class RegisterRequest(BaseModel):
    username: str
    name: str
    company_email: str
    personal_email: str
    password: str


class MicrosoftTokenRequest(BaseModel):
    id_token: Optional[str] = None
    token: Optional[str] = None

# Alternative endpoint for backward compatibility - accepts JSON
@app.post("/register/json", response_model=UserResponse)
async def register_json(user_data: RegisterRequest, db: Session = Depends(get_db)):
    """Register a new user with JSON payload (backward compat, no files)"""
    try:
        username = user_data.username
        name = user_data.name
        company_email = user_data.company_email
        personal_email = user_data.personal_email
        password = user_data.password
        
        if db.query(models.User).filter(models.User.username == username).first():
            raise HTTPException(status_code=400, detail="Username already exists")

        if db.query(models.User).filter(models.User.company_email == company_email).first():
            raise HTTPException(status_code=400, detail="Company email already exists")

        if db.query(models.User).filter(models.User.personal_email == personal_email).first():
            raise HTTPException(status_code=400, detail="Personal email already exists")

        hashed_pw = hash_password(password)

        new_user = models.User(
            username=username,
            name=name,
            company_email=company_email,
            personal_email=personal_email,
            password_hash=hashed_pw,
            role="user"
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # Generate default avatar
        photo_path = generate_default_avatar(name, new_user.id)
        if photo_path:
            new_user.profile_photo = photo_path
            db.commit()
            db.refresh(new_user)

        return new_user

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Registration error: {str(e)}")

# Main register endpoint - accepts form-data or JSON with optional file
@app.post("/register", response_model=UserResponse)
async def register(
    request: Request,
    photo: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db)
):
    """Register a new user with optional photo upload via form-data or JSON"""
    try:
        # Parse request body
        content_type = request.headers.get('content-type', '')
        
        if 'application/json' in content_type:
            # JSON payload
            body = await request.json()
            username = body.get('username')
            name = body.get('name')
            company_email = body.get('company_email')
            personal_email = body.get('personal_email')
            password = body.get('password')
        else:
            # Form data payload
            form = await request.form()
            username = form.get('username')
            name = form.get('name')
            company_email = form.get('company_email')
            personal_email = form.get('personal_email')
            password = form.get('password')
            # photo is already extracted
        
        # Validate required fields
        if not all([username, name, company_email, personal_email, password]):
            raise HTTPException(status_code=400, detail="Missing required fields")
        
        if db.query(models.User).filter(models.User.username == username).first():
            raise HTTPException(status_code=400, detail="Username already exists")

        if db.query(models.User).filter(models.User.company_email == company_email).first():
            raise HTTPException(status_code=400, detail="Company email already exists")

        if db.query(models.User).filter(models.User.personal_email == personal_email).first():
            raise HTTPException(status_code=400, detail="Personal email already exists")

        hashed_pw = hash_password(password)

        new_user = models.User(
            username=username,
            name=name,
            company_email=company_email,
            personal_email=personal_email,
            password_hash=hashed_pw,
            role="user"  # Force to user role regardless of input
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # Handle photo upload or generate default avatar
        photo_path = None
        if photo:
            photo_path = await save_user_photo(photo, new_user.id)
        
        # If no photo provided, generate default avatar with initials
        if not photo_path:
            photo_path = generate_default_avatar(name, new_user.id)
        
        # Update user with photo path
        if photo_path:
            new_user.profile_photo = photo_path
            db.commit()
            db.refresh(new_user)

        return new_user

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Registration error: {str(e)}")

# Root Route
@app.get("/")
def home():
    return {"message": "Backend is running 🚀 Use /docs for Swagger UI"}

# LOGIN endpoint follows...# ---------------- LOGIN ----------------
@app.post("/login", response_model=EnhancedTokenResponse)
async def login(credentials: UserLogin, request: Request, db: Session = Depends(get_db)):
    """
    PHASE 1: Enhanced login with full session tracking
    
    Features:
    - IP address extraction
    - Geolocation lookup
    - User-agent parsing
    - Session creation
    - Failed login tracking
    - Account locking after 5 failed attempts
    - Risk scoring
    - Comprehensive logging
    """
    try:
        # Find user by company email, personal email, or username
        user = db.query(models.User).filter(
            (models.User.company_email == credentials.username) |
            (models.User.personal_email == credentials.username) |
            (models.User.username == credentials.username)
        ).first()

        # Extract request metadata
        ip_address = get_client_ip(request)
        user_agent_info = get_user_agent_info(request)
        location_data = await get_location_from_ip(ip_address)
        location_string = get_location_string(location_data)

        # =====================================================================
        # FAILED LOGIN HANDLING
        # =====================================================================
        if not user or not user.password_hash or not verify_password(credentials.password, user.password_hash):
            failed_attempts_count = (user.failed_login_attempts + 1) if user else 0
            multiple_failed = failed_attempts_count >= 3
            risk_score = calculate_login_risk_score(
                different_country=False,
                multiple_failed_attempts=multiple_failed,
                new_device=False,
                multiple_simultaneous_sessions=False
            )
            risk_status = get_risk_status(risk_score)

            # Log failed login attempt
            failed_log = models.Log(
                user_id=user.id if user else None,
                event_type="LOGIN_FAILED",
                action="Failed Login Attempt",
                details=f"Invalid credentials for {credentials.username}",
                ip_address=ip_address,
                location=location_string,
                device=user_agent_info.get("device", "Unknown"),
                browser=user_agent_info.get("browser"),
                os=user_agent_info.get("os"),
                risk_score=risk_score,
                status=risk_status,
                # Legacy fields
                ip=ip_address,
                time=datetime.now(timezone.utc)
            )
            db.add(failed_log)

            # Increment failed attempts if user exists
            if user:
                user.failed_login_attempts = failed_attempts_count

                # Lock account after 5 failed attempts
                if user.failed_login_attempts >= 5:
                    user.account_locked = True
                    user.locked_at = datetime.now(timezone.utc)
                    user.status = "locked"

                    # Log account lock
                    lock_log = models.Log(
                        user_id=user.id,
                        event_type="ACCOUNT_LOCKED",
                        action="Account Locked",
                        details=f"Account locked after {user.failed_login_attempts} failed login attempts",
                        ip_address=ip_address,
                        location=location_string,
                        device=user_agent_info.get("device", "Unknown"),
                        browser=user_agent_info.get("browser"),
                        os=user_agent_info.get("os"),
                        risk_score=7,
                        status="suspicious",
                        ip=ip_address,
                        time=datetime.now(timezone.utc)
                    )
                    db.add(lock_log)

                db.commit()
            else:
                db.commit()

            raise HTTPException(
                status_code=401,
                detail="Invalid credentials. Account will be locked after 5 failed attempts."
            )

        # =====================================================================
        # CHECK ACCOUNT LOCK
        # =====================================================================
        if user.account_locked:
            raise HTTPException(
                status_code=403,
                detail="Account is locked due to multiple failed login attempts. Please contact administrator."
            )

        # =====================================================================
        # CHECK DEVICE REGISTRATION (Agent-based only)
        # =====================================================================
        # Require device_uuid from agent token system
        device = None
        device_id_for_session = None
        
        if credentials.device_uuid:
            # Query device by UUID and user (agent-registered devices only)
            device = db.query(models.Device).filter(
                models.Device.device_uuid == credentials.device_uuid,
                models.Device.user_id == user.id
            ).first()
            
            if device:
                # Update last seen for existing agent device
                device.last_seen_at = datetime.now(timezone.utc)
                device_id_for_session = device.id
                
                # Check if device is inactive
                if not device.is_active:
                    # Log device blocked event
                    device_blocked_log = models.Log(
                        user_id=user.id,
                        event_type="DEVICE_BLOCKED",
                        action="Login Denied - Inactive Device",
                        details=f"Login attempt with inactive device: {device.device_name} (UUID: {device.device_uuid})",
                        ip_address=ip_address,
                        location=location_string,
                        device=user_agent_info.get("device", "Unknown"),
                        browser=user_agent_info.get("browser"),
                        os=user_agent_info.get("os"),
                        risk_score=8,
                        status="blocked",
                        ip=ip_address,
                        time=datetime.now(timezone.utc)
                    )
                    db.add(device_blocked_log)
                    db.commit()

                    raise HTTPException(
                        status_code=403,
                        detail="Device is inactive. Please re-register."
                    )

                    # Check if device trust score is below threshold
                    if device.trust_score < 40:
                        # Log device untrusted event
                        device_untrusted_log = models.Log(
                            user_id=user.id,
                            event_type="DEVICE_UNTRUSTED",
                            action="Login Denied - Low Device Trust",
                            details=f"Login attempt with untrusted device: {device.device_name} (Trust Score: {device.trust_score})",
                            ip_address=ip_address,
                            location=location_string,
                            device=user_agent_info.get("device", "Unknown"),
                            browser=user_agent_info.get("browser"),
                            os=user_agent_info.get("os"),
                            risk_score=7,
                            status="untrusted",
                            ip=ip_address,
                            time=datetime.now(timezone.utc)
                        )
                        db.add(device_untrusted_log)
                        db.commit()

                        raise HTTPException(
                            status_code=403,
                            detail="Device trust score is too low. Please verify your device or re-register."
                        )
        # =====================================================================
        # SUCCESSFUL LOGIN
        # =====================================================================
        
        # Phase 2 risk scoring signals
        last_country = user.last_login_country
        current_country = location_data.get("country")
        different_country = (
            bool(last_country) and bool(current_country) and
            current_country not in ("Unknown", "Local") and
            last_country not in ("Unknown", "Local") and
            last_country != current_country
        )

        multiple_failed_attempts = user.failed_login_attempts >= 3

        existing_device = db.query(models.Session).filter(
            models.Session.user_id == user.id,
            models.Session.device == user_agent_info.get("device")
        ).first()
        new_device = existing_device is None

        active_sessions_count = db.query(models.Session).filter(
            models.Session.user_id == user.id,
            models.Session.is_active == True
        ).count()
        multiple_simultaneous_sessions = active_sessions_count >= 1

        risk_score = calculate_login_risk_score(
            different_country=different_country,
            multiple_failed_attempts=multiple_failed_attempts,
            new_device=new_device,
            multiple_simultaneous_sessions=multiple_simultaneous_sessions
        )
        risk_status = get_risk_status(risk_score)

        # Create session (device_id nullable for non-agent logins)
        session = models.Session(
            session_id=str(uuid.uuid4()),
            user_id=user.id,
            device_id=device_id_for_session,  # Link session to agent device (can be None)
            ip_address=ip_address,
            country=location_data.get("country"),
            city=location_data.get("city"),
            browser=user_agent_info.get("browser"),
            os=user_agent_info.get("os"),
            device=user_agent_info.get("device"),
            user_agent=user_agent_info.get("full_string"),
            login_at=datetime.now(timezone.utc),
            is_active=True
        )
        db.add(session)

        # Create success log
        device_info = f" with agent device: {device.device_name} (UUID: {device.device_uuid})" if device else ""
        success_log = models.Log(
            user_id=user.id,
            event_type="LOGIN_SUCCESS",
            action="Successful Login",
            details=f"User {user.username} logged in successfully{device_info}",
            ip_address=ip_address,
            location=location_string,
            device=user_agent_info.get("device", "Unknown"),
            browser=user_agent_info.get("browser"),
            os=user_agent_info.get("os"),
            risk_score=risk_score,
            status=risk_status,
            # Legacy fields
            ip=ip_address,
            time=datetime.now(timezone.utc)
        )
        db.add(success_log)

        # Update user fields
        user.last_login_at = datetime.now(timezone.utc)
        user.last_login = datetime.now(timezone.utc)  # Legacy field
        user.failed_login_attempts = 0  # Reset counter on successful login
        user.last_login_country = current_country
        user.login_ip_history = update_login_ip_history(user, ip_address)

        # Update device last_seen_at if agent device was used
        if device:
            device.last_seen_at = datetime.now(timezone.utc)

        # Commit all changes
        db.commit()
        db.refresh(session)

        # Generate tokens with optional device binding
        access_token = create_access_token({
            "sub": str(user.id),  # user ID as string (JWT requirement)
            "device_id": device_id_for_session,  # bind session to agent device (can be None)
            "session_id": session.session_id  # unique session identifier
        })
        refresh_token = create_refresh_token({
            "sub": str(user.id),
            "device_id": device_id_for_session,
            "session_id": session.session_id
        })

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "role": user.role,
            "username": user.username,
            "session_id": session.session_id,
            "device": user_agent_info.get("device", "Unknown"),
            "device_id": device_id_for_session,
            "location": location_string
        }

    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Login error: {str(e)}")

# ---------------- REFRESH TOKEN ----------------
@app.post("/login/microsoft", response_model=EnhancedTokenResponse)
async def login_microsoft(req: MicrosoftTokenRequest, request: Request, db: Session = Depends(get_db)):
    """Microsoft OAuth sign-in endpoint"""
    try:
        token = (req.id_token or req.token or "").strip()
        if not token:
            raise HTTPException(status_code=400, detail="Missing Microsoft id_token")

        logger.info("Microsoft login request token_length=%s", len(token))
        user_info = await verify_microsoft_token(token)
        user = get_or_create_microsoft_user(user_info, db)

        ip_address = get_client_ip(request)
        user_agent_info = get_user_agent_info(request)
        location_data = await get_location_from_ip(ip_address)
        location_string = get_location_string(location_data)

        session = models.Session(
            session_id=str(uuid.uuid4()),
            user_id=user.id,
            device_id=None,
            ip_address=ip_address,
            country=location_data.get("country"),
            city=location_data.get("city"),
            browser=user_agent_info.get("browser"),
            os=user_agent_info.get("os"),
            device=user_agent_info.get("device"),
            user_agent=user_agent_info.get("full_string"),
            login_at=datetime.now(timezone.utc),
            is_active=True
        )
        db.add(session)

        oauth_log = models.Log(
            user_id=user.id,
            event_type="LOGIN_SUCCESS",
            action="Successful Microsoft OAuth Login",
            details=f"User {user.username} logged in via Microsoft OAuth",
            ip_address=ip_address,
            location=location_string,
            device=user_agent_info.get("device", "Unknown"),
            browser=user_agent_info.get("browser"),
            os=user_agent_info.get("os"),
            risk_score=0,
            status="normal",
            ip=ip_address,
            time=datetime.now(timezone.utc)
        )
        db.add(oauth_log)

        user.last_login_at = datetime.now(timezone.utc)
        user.last_login = datetime.now(timezone.utc)
        user.failed_login_attempts = 0
        user.last_login_country = location_data.get("country")
        user.login_ip_history = update_login_ip_history(user, ip_address)

        db.commit()
        db.refresh(session)

        access_token = create_access_token({
            "sub": str(user.id),
            "device_id": None,
            "session_id": session.session_id
        })
        refresh_token = create_refresh_token({
            "sub": str(user.id),
            "device_id": None,
            "session_id": session.session_id
        })

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "role": user.role,
            "username": user.username,
            "session_id": session.session_id,
            "device": user_agent_info.get("device", "Unknown"),
            "location": location_string
        }

    except ValueError as e:
        db.rollback()
        logger.warning("Microsoft OAuth validation error: %s", str(e))
        raise HTTPException(status_code=401, detail=f"Microsoft OAuth error: {str(e)}")
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.exception("Microsoft login internal error")
        raise HTTPException(status_code=500, detail="Microsoft login error")


@app.post("/refresh-token", response_model=TokenResponse)
def refresh_token(token: str = Query(...), db: Session = Depends(get_db)):
    """Refresh an expired access token with device-bound session validation"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id_str = payload.get("sub")
        device_id = payload.get("device_id")
        session_id = payload.get("session_id")

        if user_id_str is None or device_id is None or session_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        try:
            user_id = int(user_id_str)
        except (ValueError, TypeError):
            raise HTTPException(status_code=401, detail="Invalid token")

        # Validate session (stateful refresh enforcement)
        session = db.query(models.Session).filter(
            models.Session.session_id == session_id,
            models.Session.user_id == user_id
        ).first()

        if session is None:
            raise HTTPException(status_code=401, detail="Session not found")

        # Server-side session expiration enforcement (if configured)
        if hasattr(session, "expires_at") and session.expires_at:
            if session.expires_at < datetime.now(timezone.utc):
                raise HTTPException(status_code=401, detail="Session expired")

        if not session.is_active:
            raise HTTPException(status_code=401, detail="Session revoked")

        if session.device_id != device_id:
            raise HTTPException(status_code=403, detail="Session not bound to device")

        # Validate device ownership and status
        device = db.query(models.Device).filter(
            models.Device.id == device_id,
            models.Device.user_id == user_id
        ).first()

        if device is None:
            raise HTTPException(status_code=401, detail="Device not found")

        if not device.is_active:
            raise HTTPException(status_code=403, detail="Device has been deactivated")

        if device.trust_score < 40:
            raise HTTPException(status_code=403, detail="Device trust score is too low")

        user = db.query(models.User).filter(models.User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        access_token = create_access_token({
            "sub": str(user.id),
            "device_id": device.id,
            "session_id": session.session_id
        })
        refresh_token_new = create_refresh_token({
            "sub": str(user.id),
            "device_id": device.id,
            "session_id": session.session_id
        })

        return {
            "access_token": access_token,
            "refresh_token": refresh_token_new,
            "token_type": "bearer",
            "role": user.role,
            "username": user.username
        }
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# ============================================================================
# GOOGLE OAUTH LOGIN
# ============================================================================
class GoogleTokenRequest(BaseModel):
    token: str


@app.post("/login/google", response_model=EnhancedTokenResponse)
async def login_google(req: GoogleTokenRequest, request: Request, db: Session = Depends(get_db)):
    """Google OAuth sign-in endpoint."""
    try:
        if not req.token or not req.token.strip():
            raise HTTPException(status_code=400, detail="Missing Google id_token")

        user_info = await verify_google_token(req.token)
        user = get_or_create_google_user(user_info, db)

        ip_address = get_client_ip(request)
        user_agent_info = get_user_agent_info(request)
        location_data = await get_location_from_ip(ip_address)
        location_string = get_location_string(location_data)

        session = models.Session(
            session_id=str(uuid.uuid4()),
            user_id=user.id,
            device_id=None,
            ip_address=ip_address,
            country=location_data.get("country"),
            city=location_data.get("city"),
            browser=user_agent_info.get("browser"),
            os=user_agent_info.get("os"),
            device=user_agent_info.get("device"),
            user_agent=user_agent_info.get("full_string"),
            login_at=datetime.now(timezone.utc),
            is_active=True,
        )
        db.add(session)

        oauth_log = models.Log(
            user_id=user.id,
            event_type="LOGIN_SUCCESS",
            action="Successful Google OAuth Login",
            details=f"User {user.username} logged in via Google OAuth",
            ip_address=ip_address,
            location=location_string,
            device=user_agent_info.get("device", "Unknown"),
            browser=user_agent_info.get("browser"),
            os=user_agent_info.get("os"),
            risk_score=0,
            status="normal",
            ip=ip_address,
            time=datetime.now(timezone.utc),
        )
        db.add(oauth_log)

        user.last_login_at = datetime.now(timezone.utc)
        user.last_login = datetime.now(timezone.utc)
        user.failed_login_attempts = 0
        user.last_login_country = location_data.get("country")
        user.login_ip_history = update_login_ip_history(user, ip_address)

        db.commit()
        db.refresh(session)

        access_token = create_access_token({
            "sub": str(user.id),
            "device_id": None,
            "session_id": session.session_id,
        })
        refresh_token = create_refresh_token({
            "sub": str(user.id),
            "device_id": None,
            "session_id": session.session_id,
        })

        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "role": user.role,
            "username": user.username,
            "session_id": session.session_id,
            "device": user_agent_info.get("device", "Unknown"),
            "location": location_string,
        }

    except ValueError as e:
        db.rollback()
        raise HTTPException(status_code=401, detail=f"Google OAuth error: {str(e)}")
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        logger.exception("Google login internal error")
        raise HTTPException(status_code=500, detail="Google login error")

# ============================================================================
# LOGOUT ----------------
# ============================================================================
@app.post("/logout")
async def logout(request: Request, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    """
    PHASE 1: Enhanced logout with session tracking
    
    Features:
    - Find and close active session
    - Update last_logout_at
    - Create logout log with full metadata
    """
    try:
        # Extract request metadata
        ip_address = get_client_ip(request)
        user_agent_info = get_user_agent_info(request)
        location_data = await get_location_from_ip(ip_address)
        location_string = get_location_string(location_data)

        # Find active session for this user
        active_session = db.query(models.Session).filter(
            models.Session.user_id == current_user.id,
            models.Session.is_active == True
        ).order_by(models.Session.login_at.desc()).first()

        # Close session if found
        if active_session:
            active_session.logout_at = datetime.now(timezone.utc)
            active_session.is_active = False

        # Update user logout time
        current_user.last_logout_at = datetime.now(timezone.utc)

        # Create logout log
        logout_log = models.Log(
            user_id=current_user.id,
            event_type="LOGOUT",
            action="User Logout",
            details=f"User {current_user.username} logged out",
            ip_address=ip_address,
            location=location_string,
            device=user_agent_info.get("device", "Unknown"),
            browser=user_agent_info.get("browser"),
            os=user_agent_info.get("os"),
            risk_score=0.0,
            status="normal",
            # Legacy fields
            ip=ip_address,
            time=datetime.now(timezone.utc)
        )
        db.add(logout_log)
        db.commit()

        return {
            "message": f"User {current_user.username} logged out successfully",
            "session_closed": active_session is not None,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Logout error: {str(e)}")

# ---------------- Protected Profile ----------------
@app.get("/profile", response_model=UserResponse)
def profile(current_user=Depends(get_current_user)):
    """Get current user profile"""
    return current_user

# ---------------- Update Profile Photo ----------------
@app.post("/profile/photo", response_model=UserResponse)
async def update_profile_photo(photo: UploadFile = File(...), db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    """Update current user's profile photo"""
    try:
        # Save the uploaded photo
        photo_path = await save_user_photo(photo, current_user.id)
        if not photo_path:
            raise HTTPException(status_code=400, detail="Failed to save photo")
        
        # Update user's profile photo in database
        user = db.query(models.User).filter(models.User.id == current_user.id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        user.profile_photo = photo_path
        db.commit()
        db.refresh(user)
        
        return user
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Photo update error: {str(e)}")

# Admin Panel ----------------
@app.get("/admin/dashboard")
def admin_dashboard(current_user=Depends(admin_required)):
    """Admin dashboard (admin access required)"""
    return {"message": "Admin Access OK", "user": current_user.username}

# ---------------- Update User Role (Admin Only) ----------------
@app.put("/admin/users/{user_id}/role", response_model=UserResponse)
def update_user_role(user_id: int, new_role: str, db: Session = Depends(get_db), current_user=Depends(admin_required)):
    """Update a user's role (admin only) and return the updated user"""
    try:
        if new_role not in ["user", "admin", "superadmin"]:
            raise HTTPException(status_code=400, detail="Invalid role. Use: user, admin, or superadmin")
        
        user = db.query(models.User).filter(models.User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        user.role = new_role
        db.commit()
        db.refresh(user)

        return user
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")

# ---------------- Log Collector (AUTH REQUIRED) ----------------
@app.post("/collect-log", response_model=dict)
def collect_log(log_data: LogCreate, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    """
    Collect activity logs from agents (AUTHENTICATION REQUIRED)
    
    Note: This endpoint uses the username field from the agent to resolve user_id.
    Agents should be configured with proper authentication if needed.
    """
    try:
        # Ensure the requester is authorized to submit a log for the given username
        if current_user.username != log_data.username and current_user.role not in ("admin", "superadmin"):
            raise HTTPException(status_code=403, detail="Not authorized to submit logs for this user")

        # Resolve username to user_id
        user_id = get_user_id_by_username(log_data.username, db)

        # Create log record
        log = Log(
            user_id=user_id,
            action=log_data.action,
            details=log_data.details,
            ip=log_data.ip,
            device=log_data.device
        )
        db.add(log)
        db.commit()
        db.refresh(log)

        return {
            "message": "Log stored successfully",
            "log_id": log.id,
            "user_id": log.user_id,
            "action": log.action,
            "time": log.time
        }
    except HTTPException:
        db.rollback()
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error storing log: {str(e)}")

# ---------------- View Logs (Admin Only) ----------------
@app.get("/logs", response_model=list[LogResponse])
def get_logs(
    skip: int = Query(0, ge=0, description="Number of logs to skip"),
    limit: int = Query(50, ge=1, le=500, description="Number of logs to return (max 500)"),
    db: Session = Depends(get_db),
    current_user=Depends(admin_required)
):
    """Get activity logs with pagination (admin only)"""
    try:
        query = db.query(Log)

        # Admins can only see logs for users with role == "user"
        if current_user.role == "admin":
            query = query.join(models.User, models.User.id == Log.user_id).filter(models.User.role == "user")

        logs = query.order_by(Log.time.desc()).offset(skip).limit(limit).all()
        return logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching logs: {str(e)}")

# ---------------- Search Logs (Admin Only) ----------------
@app.get("/logs/search", response_model=list[LogResponse])
def search_logs(
    action: str = Query(None, description="Filter by action type"),
    user_id: int = Query(None, description="Filter by user_id"),
    ip: str = Query(None, description="Filter by IP address"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user=Depends(admin_required)
):
    """Search logs with filters (admin only)"""
    try:
        query = db.query(Log)

        # Admins can only see logs for users with role == "user"
        if current_user.role == "admin":
            query = query.join(models.User, models.User.id == Log.user_id).filter(models.User.role == "user")
        
        if action:
            query = query.filter(Log.action.ilike(f"%{action}%"))
        if user_id:
            query = query.filter(Log.user_id == user_id)
        if ip:
            query = query.filter(Log.ip == ip)
        
        logs = query.order_by(Log.time.desc()).offset(skip).limit(limit).all()
        return logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error searching logs: {str(e)}")

# ---------------- Admin Profile ----------------
@app.get("/admin/profile", response_model=UserResponse)
def admin_profile(current_user=Depends(admin_required)):
    """Return the current admin profile"""
    return current_user


# ---------------- Admin Logs (alias) ----------------
@app.get("/admin/logs", response_model=list[LogResponse])
def admin_logs(
    skip: int = Query(0, ge=0, description="Number of logs to skip"),
    limit: int = Query(50, ge=1, le=500, description="Number of logs to return (max 500)"),
    db: Session = Depends(get_db),
    current_user=Depends(admin_required)
):
    """Admin endpoint to fetch recent logs (same as /logs)"""
    try:
        query = db.query(Log)

        # Admins can only see logs for users with role == "user"
        if current_user.role == "admin":
            query = query.join(models.User, models.User.id == Log.user_id).filter(models.User.role == "user")

        logs = query.order_by(Log.time.desc()).offset(skip).limit(limit).all()
        return logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching admin logs: {str(e)}")


# ---------------- Admin Logs (enhanced) ----------------
@app.get("/admin/logs/enhanced", response_model=list[EnhancedLogResponse])
def admin_logs_enhanced(
    skip: int = Query(0, ge=0, description="Number of logs to skip"),
    limit: int = Query(50, ge=1, le=500, description="Number of logs to return (max 500)"),
    status: str = Query(None, description="Filter by status (normal/suspicious)"),
    event_type: str = Query(None, description="Filter by event type"),
    db: Session = Depends(get_db),
    current_user=Depends(admin_required)
):
    """Admin endpoint to fetch enhanced logs with risk scoring"""
    try:
        query = db.query(Log)

        if current_user.role == "admin":
            query = query.join(models.User, models.User.id == Log.user_id).filter(models.User.role == "user")

        if status:
            query = query.filter(Log.status == status)
        if event_type:
            query = query.filter(Log.event_type == event_type)

        logs = query.order_by(Log.timestamp.desc()).offset(skip).limit(limit).all()
        return logs
    except Exception:
        raise HTTPException(status_code=500, detail="Unable to fetch enhanced logs")


@app.get("/admin/logs/export")
def export_logs_csv(
    event_type: str = Query(None, description="Filter by event type"),
    status: str = Query(None, description="Filter by status"),
    user_id: int = Query(None, description="Filter by user id"),
    suspicious: bool = Query(False, description="Only suspicious logs"),
    start_date: str = Query(None, description="Start date (ISO 8601)"),
    end_date: str = Query(None, description="End date (ISO 8601)"),
    db: Session = Depends(get_db),
    current_user=Depends(admin_required)
):
    """Admin: Export logs as CSV"""
    try:
        query = db.query(Log)

        if current_user.role == "admin":
            query = query.join(models.User, models.User.id == Log.user_id).filter(models.User.role == "user")

        if user_id:
            query = query.filter(Log.user_id == user_id)

        if event_type:
            query = query.filter(Log.event_type == event_type.strip())

        if status:
            query = query.filter(Log.status == status.strip())

        if suspicious:
            query = query.filter(Log.status == "suspicious")

        start_dt = parse_iso_datetime(start_date)
        end_dt = parse_iso_datetime(end_date)
        if start_dt:
            query = query.filter(Log.timestamp >= start_dt)
        if end_dt:
            query = query.filter(Log.timestamp <= end_dt)

        logs = query.order_by(Log.timestamp.desc()).all()

        import csv
        from io import StringIO
        from fastapi.responses import StreamingResponse

        output = StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "id", "user_id", "event_type", "action", "details", "ip_address",
            "location", "device", "browser", "os", "risk_score", "status", "timestamp"
        ])
        for log in logs:
            writer.writerow([
                log.id,
                log.user_id,
                log.event_type,
                log.action,
                log.details,
                log.ip_address or log.ip,
                log.location,
                log.device,
                log.browser,
                log.os,
                log.risk_score,
                log.status,
                (log.timestamp or log.time).isoformat() if (log.timestamp or log.time) else ""
            ])

        output.seek(0)
        headers = {"Content-Disposition": "attachment; filename=admin_logs_export.csv"}
        return StreamingResponse(iter([output.getvalue()]), media_type="text/csv", headers=headers)
    except Exception:
        raise HTTPException(status_code=500, detail="Unable to export logs")


# ---------------- Get All Users (Admin Only) ----------------
@app.get("/admin/users", response_model=AdminUsersResponse)
def get_all_users(
    search: str = Query(None, description="Search by username or name"),
    role: str = Query(None, description="Filter by role"),
    user_id: int = Query(None, description="Filter by user id"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user=Depends(admin_required)
):
    """Admin monitoring users list with pagination and active session count"""
    try:
        search_value = search.strip() if search else None
        role_value = role.strip() if role else None

        # Base user query
        user_query = db.query(models.User)

        # Admins can only see regular users
        if current_user.role == "admin":
            user_query = user_query.filter(models.User.role == "user")

        if user_id:
            user_query = user_query.filter(models.User.id == user_id)

        if role_value:
            user_query = user_query.filter(models.User.role == role_value)

        if search_value:
            like = f"%{search_value}%"
            user_query = user_query.filter(
                (models.User.username.ilike(like)) |
                (models.User.name.ilike(like)) |
                (models.User.company_email.ilike(like)) |
                (models.User.personal_email.ilike(like))
            )

        total = user_query.with_entities(func.count(models.User.id)).scalar() or 0
        offset = (page - 1) * limit

        active_sessions_subq = (
            db.query(
                models.Session.user_id.label("user_id"),
                func.count(models.Session.id).label("active_session_count")
            )
            .filter(models.Session.is_active == True)
            .group_by(models.Session.user_id)
            .subquery()
        )

        rows = (
            user_query
            .outerjoin(active_sessions_subq, models.User.id == active_sessions_subq.c.user_id)
            .add_columns(func.coalesce(active_sessions_subq.c.active_session_count, 0).label("active_session_count"))
            .order_by(models.User.id.asc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        data = []
        for user, active_session_count in rows:
            user_data = AdminUserOut.model_validate(user).model_dump()
            user_data["active_session_count"] = int(active_session_count or 0)
            data.append(user_data)

        return {
            "data": data,
            "pagination": build_pagination(total, page, limit)
        }
    except Exception:
        raise HTTPException(status_code=500, detail="Unable to fetch users")


# ---------------- Get All Users (Superadmin Only) ----------------
@app.get("/admin/users/all", response_model=AdminUsersResponse)
def get_all_users_superadmin(
    search: str = Query(None, description="Search by username or name"),
    role: str = Query(None, description="Filter by role"),
    user_id: int = Query(None, description="Filter by user id"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user=Depends(admin_required)
):
    """Superadmin endpoint to fetch all users, including admins"""
    if not is_superadmin(current_user):
        raise HTTPException(status_code=403, detail="Superadmin access required")

    try:
        search_value = search.strip() if search else None
        role_value = role.strip() if role else None

        query = db.query(models.User)

        if user_id:
            query = query.filter(models.User.id == user_id)

        if role_value:
            query = query.filter(models.User.role == role_value)

        if search_value:
            like = f"%{search_value}%"
            query = query.filter(
                (models.User.username.ilike(like)) |
                (models.User.name.ilike(like)) |
                (models.User.company_email.ilike(like)) |
                (models.User.personal_email.ilike(like))
            )

        total = query.with_entities(func.count(models.User.id)).scalar() or 0
        offset = (page - 1) * limit

        active_sessions_subq = (
            db.query(
                models.Session.user_id.label("user_id"),
                func.count(models.Session.id).label("active_session_count")
            )
            .filter(models.Session.is_active == True)
            .group_by(models.Session.user_id)
            .subquery()
        )

        rows = (
            query
            .outerjoin(active_sessions_subq, models.User.id == active_sessions_subq.c.user_id)
            .add_columns(func.coalesce(active_sessions_subq.c.active_session_count, 0).label("active_session_count"))
            .order_by(models.User.id.asc())
            .offset(offset)
            .limit(limit)
            .all()
        )

        data = []
        for user, active_session_count in rows:
            user_data = AdminUserOut.model_validate(user).model_dump()
            user_data["active_session_count"] = int(active_session_count or 0)
            data.append(user_data)

        return {
            "data": data,
            "pagination": build_pagination(total, page, limit)
        }
    except Exception:
        raise HTTPException(status_code=500, detail="Unable to fetch users")


# ---------------- Lock/Unlock User Account ----------------
@app.post("/admin/users/{user_id}/lock-unlock")
def lock_unlock_user(
    user_id: int,
    request_data: LockUnlockRequestCreate,
    db: Session = Depends(get_db),
    current_user=Depends(admin_required)
):
    """
    Lock or unlock a user account.
    - Superadmin: Direct action
    - Admin: Creates request for superadmin approval
    """
    import json
    
    try:
        # Fetch target user
        target_user = db.query(models.User).filter(models.User.id == user_id).first()
        if not target_user:
            raise HTTPException(status_code=404, detail="User not found")
        
        # Prevent self-targeting
        if target_user.id == current_user.id:
            raise HTTPException(status_code=400, detail="Cannot lock/unlock yourself")
        
        # Validate action
        if request_data.action not in ["lock", "unlock"]:
            raise HTTPException(status_code=400, detail="Action must be 'lock' or 'unlock'")
        
        # Check if action is already in desired state
        is_locked = target_user.account_locked or target_user.status == "locked"
        if request_data.action == "lock" and is_locked:
            raise HTTPException(status_code=400, detail="User is already locked")
        if request_data.action == "unlock" and not is_locked:
            raise HTTPException(status_code=400, detail="User is not locked")
        
        # SUPERADMIN: Execute directly
        if is_superadmin(current_user):
            if request_data.action == "lock":
                target_user.account_locked = True
                target_user.status = "locked"
                target_user.locked_at = datetime.now(timezone.utc)
                
                # Terminate all active sessions
                db.query(models.Session).filter(
                    models.Session.user_id == user_id,
                    models.Session.is_active == True
                ).update({"is_active": False, "logout_at": datetime.now(timezone.utc)})
                
                # Log the action
                log = models.Log(
                    user_id=user_id,
                    event_type="ACCOUNT_LOCKED",
                    action=f"Account locked by superadmin {current_user.username}",
                    details=f"Reason: {request_data.reason or 'No reason provided'}",
                    ip_address="system",
                    ip="system",
                    device="system",
                    timestamp=datetime.now(timezone.utc),
                    status="critical"
                )
                db.add(log)
                
            else:  # unlock
                target_user.account_locked = False
                target_user.status = "active"
                target_user.failed_login_attempts = 0
                target_user.locked_at = None
                
                # Log the action
                log = models.Log(
                    user_id=user_id,
                    event_type="ACCOUNT_UNLOCKED",
                    action=f"Account unlocked by superadmin {current_user.username}",
                    details=f"Reason: {request_data.reason or 'No reason provided'}",
                    ip_address="system",
                    ip="system",
                    device="system",
                    timestamp=datetime.now(timezone.utc),
                    status="normal"
                )
                db.add(log)
            
            db.commit()
            return {
                "success": True,
                "message": f"User {request_data.action}ed successfully",
                "action": "executed"
            }
        
        # ADMIN: Create approval request
        else:
            # Calculate current risk score for context
            risk_score = 0.0
            if hasattr(target_user, 'failed_login_attempts') and target_user.failed_login_attempts >= 3:
                risk_score += 3.0
            
            # Prepare user details for context
            user_details = json.dumps({
                "username": target_user.username,
                "email": target_user.company_email,
                "role": target_user.role,
                "failed_attempts": target_user.failed_login_attempts,
                "last_login_country": target_user.last_login_country,
                "account_locked": target_user.account_locked,
                "status": target_user.status
            })
            
            # Create request
            lock_request = models.LockUnlockRequest(
                user_id=user_id,
                requested_by_id=current_user.id,
                action=request_data.action,
                reason=request_data.reason,
                risk_score=risk_score,
                user_details=user_details,
                status="pending",
                created_at=datetime.now(timezone.utc)
            )
            db.add(lock_request)
            db.commit()
            db.refresh(lock_request)
            
            return {
                "success": True,
                "message": f"{request_data.action.capitalize()} request sent to superadmin for approval",
                "action": "request_created",
                "request_id": lock_request.id
            }
            
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to process request: {str(e)}")


# ---------------- Get Pending Lock/Unlock Requests (Superadmin Only) ----------------
@app.get("/admin/requests/pending", response_model=PendingRequestsResponse)
def get_pending_requests(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
    current_user=Depends(admin_required)
):
    """Get all pending lock/unlock requests (superadmin only)"""
    if not is_superadmin(current_user):
        raise HTTPException(status_code=403, detail="Superadmin access required")
    
    try:
        query = db.query(models.LockUnlockRequest).filter(
            models.LockUnlockRequest.status == "pending"
        )
        
        total = query.with_entities(func.count(models.LockUnlockRequest.id)).scalar() or 0
        offset = (page - 1) * limit
        
        requests = query.order_by(models.LockUnlockRequest.created_at.desc()).offset(offset).limit(limit).all()
        
        # Enrich with usernames
        data = []
        for req in requests:
            req_dict = LockUnlockRequestResponse.model_validate(req).model_dump()
            
            # Get target user
            target_user = db.query(models.User).filter(models.User.id == req.user_id).first()
            req_dict["target_username"] = target_user.username if target_user else "Unknown"
            
            # Get requester
            requester = db.query(models.User).filter(models.User.id == req.requested_by_id).first()
            req_dict["requested_by_username"] = requester.username if requester else "Unknown"
            
            data.append(req_dict)
        
        return {
            "data": data,
            "pagination": build_pagination(total, page, limit)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unable to fetch requests: {str(e)}")


# ---------------- Review Lock/Unlock Request (Superadmin Only) ----------------
@app.post("/admin/requests/{request_id}/review")
def review_request(
    request_id: int,
    review: ReviewRequestAction,
    db: Session = Depends(get_db),
    current_user=Depends(admin_required)
):
    """Approve or reject a lock/unlock request (superadmin only)"""
    if not is_superadmin(current_user):
        raise HTTPException(status_code=403, detail="Superadmin access required")
    
    if review.action not in ["approve", "reject"]:
        raise HTTPException(status_code=400, detail="Action must be 'approve' or 'reject'")
    
    try:
        # Fetch the request
        lock_request = db.query(models.LockUnlockRequest).filter(
            models.LockUnlockRequest.id == request_id
        ).first()
        
        if not lock_request:
            raise HTTPException(status_code=404, detail="Request not found")
        
        if lock_request.status != "pending":
            raise HTTPException(status_code=400, detail=f"Request already {lock_request.status}")
        
        # Update request status
        lock_request.status = "approved" if review.action == "approve" else "rejected"
        lock_request.reviewed_by_id = current_user.id
        lock_request.reviewed_at = datetime.now(timezone.utc)
        lock_request.review_comment = review.comment
        
        # If approved, execute the action
        if review.action == "approve":
            target_user = db.query(models.User).filter(models.User.id == lock_request.user_id).first()
            
            if not target_user:
                raise HTTPException(status_code=404, detail="Target user not found")
            
            if lock_request.action == "lock":
                target_user.account_locked = True
                target_user.status = "locked"
                target_user.locked_at = datetime.now(timezone.utc)
                
                # Terminate all active sessions
                db.query(models.Session).filter(
                    models.Session.user_id == lock_request.user_id,
                    models.Session.is_active == True
                ).update({"is_active": False, "logout_at": datetime.now(timezone.utc)})
                
                # Log the action
                log = models.Log(
                    user_id=lock_request.user_id,
                    event_type="ACCOUNT_LOCKED",
                    action=f"Account locked - Request approved by {current_user.username}",
                    details=f"Requested by admin. Reason: {lock_request.reason or 'No reason provided'}",
                    ip_address="system",
                    ip="system",
                    device="system",
                    timestamp=datetime.now(timezone.utc),
                    status="critical"
                )
                db.add(log)
                
            else:  # unlock
                target_user.account_locked = False
                target_user.status = "active"
                target_user.failed_login_attempts = 0
                target_user.locked_at = None
                
                # Log the action
                log = models.Log(
                    user_id=lock_request.user_id,
                    event_type="ACCOUNT_UNLOCKED",
                    action=f"Account unlocked - Request approved by {current_user.username}",
                    details=f"Requested by admin. Reason: {lock_request.reason or 'No reason provided'}",
                    ip_address="system",
                    ip="system",
                    device="system",
                    timestamp=datetime.now(timezone.utc),
                    status="normal"
                )
                db.add(log)
        
        db.commit()
        
        return {
            "success": True,
            "message": f"Request {review.action}ed successfully",
            "action": lock_request.action if review.action == "approve" else None,
            "executed": review.action == "approve"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to review request: {str(e)}")


# ---------------- Standard Users endpoints (Admin Only) ----------------
@app.get("/users", response_model=list[UserResponse])
def get_users(
    search: str = Query(None, description="Search by username or name"),
    user_id: int = Query(None, description="Filter by user id"),
    skip: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=2000),
    db: Session = Depends(get_db),
    current_user=Depends(admin_required)
):
    """Alias for /admin/users to satisfy standard endpoint naming"""
    try:
        query = db.query(models.User)

        # Admins can only see regular users
        if current_user.role == "admin":
            query = query.filter(models.User.role == "user")

        if user_id:
            query = query.filter(models.User.id == user_id)

        if search:
            like = f"%{search}%"
            query = query.filter(
                (models.User.username.ilike(like)) | (models.User.name.ilike(like))
            )

        users = query.order_by(models.User.id.asc()).offset(skip).limit(limit).all()
        return users
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching users: {str(e)}")


@app.get("/users/{user_id}", response_model=UserResponse)
def get_user_by_id(user_id: int, db: Session = Depends(get_db), current_user=Depends(admin_required)):
    """Fetch single user by id (admin only)"""
    try:
        user = db.query(models.User).filter(models.User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        # Admins cannot view other admins or superadmins
        if current_user.role == "admin" and user.role in ("admin", "superadmin"):
            raise HTTPException(status_code=403, detail="Not authorized to view admin users")

        return user
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching user: {str(e)}")


# ---------------- User-specific Logs (Admin Only) ----------------
@app.get("/admin/users/{user_id}/logs", response_model=AdminUserLogsResponse)
def get_admin_user_logs(
    user_id: int,
    event_type: str = Query(None, description="Filter by event type"),
    suspicious: bool = Query(False, description="Only suspicious logs"),
    start_date: str = Query(None, description="Start date (ISO 8601)"),
    end_date: str = Query(None, description="End date (ISO 8601)"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user=Depends(admin_required)
):
    """Return logs for a user with filters and pagination (admin only)"""
    try:
        user = db.query(models.User).filter(models.User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")

        if current_user.role == "admin" and user.role in ("admin", "superadmin"):
            raise HTTPException(status_code=403, detail="Not authorized to view admin logs")

        query = db.query(Log).filter(Log.user_id == user_id)

        if event_type:
            query = query.filter(Log.event_type == event_type.strip())

        if suspicious:
            query = query.filter(Log.status == "suspicious")

        start_dt = parse_iso_datetime(start_date)
        end_dt = parse_iso_datetime(end_date)
        if start_dt:
            query = query.filter(Log.timestamp >= start_dt)
        if end_dt:
            query = query.filter(Log.timestamp <= end_dt)

        total = query.with_entities(func.count(Log.id)).scalar() or 0
        offset = (page - 1) * limit

        logs = query.order_by(Log.timestamp.desc()).offset(offset).limit(limit).all()

        return {
            "user_id": user.id,
            "username": user.username,
            "role": user.role,
            "data": logs,
            "pagination": build_pagination(total, page, limit)
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="Unable to fetch user logs")


@app.get("/users/{user_id}/logs")
def get_user_logs_alias(
    user_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(500, ge=1, le=2000),
    db: Session = Depends(get_db),
    current_user=Depends(admin_required)
):
    """Alias endpoint for /admin/users/{user_id}/logs - Returns logs with username and count"""
    return get_admin_user_logs(user_id, skip, limit, db, current_user)

# =============================================================================
# PHASE 1: Session Management Endpoints
# =============================================================================

@app.get("/sessions", response_model=list[SessionResponse])
def get_user_sessions(
    include_inactive: bool = Query(False, description="Include inactive/closed sessions"),
    limit: int = Query(10, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Get current user's login sessions
    
    Returns list of sessions with device, location, and timing info
    """
    try:
        query = db.query(models.Session).filter(models.Session.user_id == current_user.id)
        
        if not include_inactive:
            query = query.filter(models.Session.is_active == True)
        
        sessions = query.order_by(models.Session.login_at.desc()).limit(limit).all()
        return sessions
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching sessions: {str(e)}")


@app.get("/sessions/{session_id}", response_model=SessionResponse)
def get_session_details(
    session_id: str,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """Get details of a specific session"""
    try:
        session = db.query(models.Session).filter(
            models.Session.session_id == session_id,
            models.Session.user_id == current_user.id
        ).first()
        
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        
        return session
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching session: {str(e)}")


@app.delete("/sessions/{session_id}")
async def terminate_session(
    session_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Terminate a specific session (remote logout)
    
    Useful for logging out from other devices
    """
    try:
        session = db.query(models.Session).filter(
            models.Session.session_id == session_id,
            models.Session.user_id == current_user.id,
            models.Session.is_active == True
        ).first()
        
        if not session:
            raise HTTPException(status_code=404, detail="Active session not found")
        
        # Close session
        session.logout_at = datetime.now(timezone.utc)
        session.is_active = False
        
        # Log session termination
        ip_address = get_client_ip(request)
        user_agent_info = get_user_agent_info(request)
        location_data = await get_location_from_ip(ip_address)
        location_string = get_location_string(location_data)
        
        terminate_log = models.Log(
            user_id=current_user.id,
            event_type="SESSION_TERMINATED",
            action="Remote Session Termination",
            details=f"Session {session_id} terminated remotely",
            ip_address=ip_address,
            location=location_string,
            device=user_agent_info.get("device", "Unknown"),
            browser=user_agent_info.get("browser"),
            os=user_agent_info.get("os"),
            risk_score=0.0,
            status="normal",
            ip=ip_address,
            time=datetime.now(timezone.utc)
        )
        db.add(terminate_log)
        db.commit()
        
        return {"message": "Session terminated successfully", "session_id": session_id}
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Error terminating session: {str(e)}")


@app.get("/logs/enhanced", response_model=list[EnhancedLogResponse])
def get_enhanced_logs(
    limit: int = Query(50, ge=1, le=500),
    event_type: str = Query(None, description="Filter by event type"),
    status: str = Query(None, description="Filter by status (normal/suspicious/critical)"),
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Get user's logs with full Phase 1 enhanced fields
    
    Returns logs with event_type, risk_score, location, browser/OS info
    """
    try:
        query = db.query(models.Log).filter(models.Log.user_id == current_user.id)
        
        if event_type:
            query = query.filter(models.Log.event_type == event_type)
        
        if status:
            query = query.filter(models.Log.status == status)
        
        logs = query.order_by(models.Log.timestamp.desc()).limit(limit).all()
        return logs
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error fetching enhanced logs: {str(e)}")


@app.get("/admin/sessions", response_model=AdminSessionsResponse)
def get_all_sessions(
    user_id: int = Query(None, description="Filter by user ID"),
    active_only: bool = Query(True, description="Show only active sessions"),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user=Depends(admin_required)
):
    """
    Admin: View all user sessions across the system
    """
    try:
        query = db.query(models.Session)

        # Admins can only see sessions for users with role == "user"
        if current_user.role == "admin":
            query = query.join(models.User, models.User.id == models.Session.user_id).filter(models.User.role == "user")
        
        if user_id:
            query = query.filter(models.Session.user_id == user_id)
        
        if active_only:
            query = query.filter(models.Session.is_active == True)

        total = query.with_entities(func.count(models.Session.id)).scalar() or 0
        offset = (page - 1) * limit

        sessions = query.order_by(models.Session.login_at.desc()).offset(offset).limit(limit).all()
        return {
            "data": sessions,
            "pagination": build_pagination(total, page, limit)
        }
    except Exception:
        raise HTTPException(status_code=500, detail="Unable to fetch sessions")


@app.delete("/admin/sessions/{session_id}")
async def force_logout_session(
    session_id: str,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(admin_required)
):
    """Admin: Force logout a user session"""
    try:
        session = db.query(models.Session).filter(
            models.Session.session_id == session_id,
            models.Session.is_active == True
        ).first()

        if not session:
            raise HTTPException(status_code=404, detail="Active session not found")

        # Admins cannot terminate other admin/superadmin sessions
        if current_user.role == "admin":
            target_user = db.query(models.User).filter(models.User.id == session.user_id).first()
            if target_user and target_user.role in ("admin", "superadmin"):
                raise HTTPException(status_code=403, detail="Not authorized to terminate admin sessions")

        session.logout_at = datetime.now(timezone.utc)
        session.is_active = False

        ip_address = get_client_ip(request)
        user_agent_info = get_user_agent_info(request)
        location_data = await get_location_from_ip(ip_address)
        location_string = get_location_string(location_data)

        log = models.Log(
            user_id=session.user_id,
            event_type="SESSION_TERMINATED",
            action="Admin Force Logout",
            details=f"Session {session_id} terminated by admin",
            ip_address=ip_address,
            location=location_string,
            device=user_agent_info.get("device", "Unknown"),
            browser=user_agent_info.get("browser"),
            os=user_agent_info.get("os"),
            risk_score=0,
            status="normal",
            ip=ip_address,
            time=datetime.now(timezone.utc)
        )
        db.add(log)
        db.commit()

        return {"message": "Session terminated", "session_id": session_id}
    except HTTPException:
        raise
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="Unable to terminate session")

# =============================================================================
# DEVICE REGISTRATION ENDPOINT
# =============================================================================

@app.post("/devices/register", response_model=DeviceResponse)
async def register_device(
    device_data: DeviceRegister,
    request: Request,
    db: Session = Depends(get_db),
    current_user=Depends(get_current_user)
):
    """
    Register a new device for the authenticated user
    
    Security Rules:
    - Device UUID must be at least 32 characters
    - If device_uuid exists for current user → return existing device
    - If device_uuid exists for another user → reject with 403
    - Auto-set trust_score=100.0 and is_active=True
    
    Features:
    - Full activity logging
    - IP and location tracking
    - Autodevices/register",
        "/matic timestamp management
    """
    try:
        # Validate device UUID length
        if len(device_data.device_uuid) < 32:
            raise HTTPException(
                status_code=400,
                detail="Device UUID must be at least 32 characters"
            )
        
        # Check if device already exists
        existing_device = db.query(Device).filter(
            Device.device_uuid == device_data.device_uuid
        ).first()
        
        if existing_device:
            # If device belongs to current user, update last_seen and return
            if existing_device.user_id == current_user.id:
                existing_device.last_seen_at = datetime.now(timezone.utc)
                db.commit()
                db.refresh(existing_device)
                
                return existing_device
            else:
                # Device belongs to another user - security violation
                raise HTTPException(
                    status_code=403,
                    detail="Device UUID already registered to another user"
                )
        
        # Create new device
        new_device = Device(
            user_id=current_user.id,
            device_uuid=device_data.device_uuid,
            device_name=device_data.device_name,
            os=device_data.os,
            first_registered_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc),
            is_active=True,
            trust_score=100.0
        )
        
        db.add(new_device)
        
        # Extract request metadata for logging
        ip_address = get_client_ip(request)
        user_agent_info = get_user_agent_info(request)
        location_data = await get_location_from_ip(ip_address)
        location_string = get_location_string(location_data)
        
        # Create registration log
        registration_log = Log(
            user_id=current_user.id,
            event_type="DEVICE_REGISTERED",
            action="Device Registration",
            details=f"New device registered: {device_data.device_name} (UUID: {device_data.device_uuid[:16]}...)",
            ip_address=ip_address,
            location=location_string,
            device=user_agent_info.get("device", "Unknown"),
            browser=user_agent_info.get("browser"),
            os=user_agent_info.get("os"),
            risk_score=0.0,
            status="normal",
            ip=ip_address,
            time=datetime.now(timezone.utc),
            timestamp=datetime.now(timezone.utc)
        )
        db.add(registration_log)
        
        # Commit all changes
        db.commit()
        db.refresh(new_device)
        
        return new_device
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail=f"Device registration error: {str(e)}"
        )


# ============================================================================
# AGENT ENDPOINTS (Zero Trust Endpoint Monitoring)
# ============================================================================

@app.post("/agent/register", response_model=AgentRegisterResponse, tags=["agent"])
async def register_agent(
    request_data: AgentRegisterRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Register endpoint agent device with backend.
    
    Called by agent on first startup to establish device identity.
    Returns agent_token for subsequent heartbeat authentication.
    """
    try:
        device_uuid = request_data.device_uuid.strip()
        
        if not device_uuid:
            raise HTTPException(status_code=400, detail="device_uuid is required")
        
        # Check if device already registered
        existing_device = db.query(Device).filter_by(device_uuid=device_uuid).first()
        
        if existing_device:
            # Device already exists - issue new token
            new_token = create_access_token({
                "sub": str(existing_device.id),
                "type": "agent",
                "device_uuid": device_uuid
            })
            
            # Update last_seen and store new token hash
            existing_device.last_seen_at = datetime.now(timezone.utc)
            existing_device.agent_token_hash = hash_agent_token(new_token)
            db.commit()
            db.refresh(existing_device)
            
            logger.info(f"Agent re-registered: Device {device_uuid[:16]}... (ID: {existing_device.id})")
            
            return AgentRegisterResponse(
                agent_token=new_token,
                device_id=existing_device.id,
                registered_at=datetime.now(timezone.utc),
                heartbeat_interval=30
            )
        
        # Create new device record
        new_device = Device(
            user_id=None,  # Agent devices don't require user association initially
            device_uuid=device_uuid,
            hostname=request_data.hostname,
            os_version=request_data.os_version,
            device_name=f"{request_data.hostname} ({request_data.os_version})",
            os=request_data.os_version.split()[0] if request_data.os_version else None,
            is_active=True,
            trust_score=100.0,
            first_registered_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc)
        )
        
        # Generate and store agent token
        agent_token = create_access_token({
            "sub": str(new_device.id),
            "type": "agent",
            "device_uuid": device_uuid
        })
        
        new_device.agent_token_hash = hash_agent_token(agent_token)
        
        db.add(new_device)
        db.commit()
        db.refresh(new_device)
        
        logger.info(f"Agent registered: Device {device_uuid[:16]}... (ID: {new_device.id}) from {request_data.hostname}")
        
        # Create registration log
        registration_log = Log(
            user_id=None,
            event_type="AGENT_REGISTERED",
            action="Endpoint Agent Registration",
            details=f"New agent device registered: {request_data.hostname} ({request_data.os_version})",
            ip_address=get_client_ip(request),
            device=request_data.hostname,
            risk_score=0.0,
            status="normal",
            timestamp=datetime.now(timezone.utc)
        )
        db.add(registration_log)
        db.commit()
        
        return AgentRegisterResponse(
            agent_token=agent_token,
            device_id=new_device.id,
            registered_at=datetime.now(timezone.utc),
            heartbeat_interval=30
        )
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Agent registration error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Agent registration failed: {str(e)}"
        )


@app.post("/agent/heartbeat", response_model=AgentHeartbeatResponse, tags=["agent"])
async def receive_agent_heartbeat(
    heartbeat: AgentHeartbeatRequest,
    request: Request,
    authorization: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    Receive heartbeat and telemetry from endpoint agent.
    
    Called periodically (default every 30 seconds) to:
    - Update device last_seen timestamp
    - Store system telemetry metrics
    - Recalculate trust_score
    - Return updated device status
    
    Requires Authorization header: Bearer <agent_token>
    """
    try:
        # Extract and validate token
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
        
        token = authorization.replace("Bearer ", "").strip()
        
        # Verify token
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            token_type = payload.get("type")
            
            if token_type != "agent":
                raise HTTPException(status_code=401, detail="Invalid token type")
                
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        
        device_uuid = heartbeat.device_uuid.strip()
        
        # Find device by UUID
        device = db.query(Device).filter_by(device_uuid=device_uuid).first()
        
        if not device:
            raise HTTPException(status_code=404, detail=f"Device {device_uuid} not found")
        
        # Verify token hash matches
        if device.agent_token_hash:
            if not verify_agent_token(token, device.agent_token_hash):
                raise HTTPException(status_code=401, detail="Token mismatch")
        
        # Update device last_seen
        device.last_seen_at = datetime.now(timezone.utc)
        
        # Store telemetry snapshot
        metrics_json = json.dumps(heartbeat.metrics.dict(exclude_none=True), default=str)
        
        telemetry = Telemetry(
            device_id=device.id,
            collected_at=heartbeat.timestamp or datetime.now(timezone.utc),
            metrics=metrics_json,
            sample_count=1
        )
        
        db.add(telemetry)
        
        # Calculate updated trust_score
        suspicious_flag = False  # Can be set based on telemetry analysis
        
        # Simple anomaly detection: high CPU or memory usage could be suspicious
        if heartbeat.metrics.cpu and heartbeat.metrics.cpu.get("percent", 0) > 95:
            suspicious_flag = True
        if heartbeat.metrics.memory and heartbeat.metrics.memory.get("virtual", {}).get("percent", 0) > 95:
            suspicious_flag = True
        
        new_trust_score = calculate_agent_trust_score(
            current_score=device.trust_score,
            last_seen_at=device.last_seen_at,
            suspicious_flag=suspicious_flag
        )
        
        device.trust_score = new_trust_score
        
        # Disable device if trust_score drops below threshold
        if new_trust_score < 20:
            device.is_active = False
            logger.warning(f"Device {device.id} disabled due to low trust_score: {new_trust_score}")
        
        db.commit()
        db.refresh(device)
        
        logger.info(
            f"Agent heartbeat received: Device {device_uuid[:16]}... "
            f"(ID: {device.id}) - Trust: {new_trust_score:.1f} - "
            f"CPU: {heartbeat.metrics.cpu.get('percent', 'N/A') if heartbeat.metrics.cpu else 'N/A'}%"
        )
        
        return AgentHeartbeatResponse(
            status="success",
            message="Heartbeat received",
            device_id=device.id,
            new_trust_score=new_trust_score,
            received_at=datetime.now(timezone.utc)
        )
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Heartbeat processing error: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Heartbeat processing failed: {str(e)}"
        )


@app.get("/agent/devices", tags=["agent"])
async def get_agent_devices(
    current_user: User = Depends(admin_required),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """
    List all registered agent devices (admin only).
    """
    try:
        statement = db.query(Device)
        total = statement.count()
        
        devices = statement.offset(skip).limit(limit).all()
        
        return {
            "data": [
                {
                    "id": d.id,
                    "device_uuid": d.device_uuid,
                    "hostname": d.hostname,
                    "os_version": d.os_version,
                    "trust_score": d.trust_score,
                    "is_active": d.is_active,
                    "last_seen_at": d.last_seen_at,
                    "first_registered_at": d.first_registered_at,
                    "user_id": d.user_id
                }
                for d in devices
            ],
            "pagination": {
                "total": total,
                "skip": skip,
                "limit": limit,
                "total_pages": (total + limit - 1) // limit
            }
        }
    except Exception as e:
        logger.error(f"Error fetching agent devices: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch devices")


@app.get("/agent/devices/{device_id}/telemetry", tags=["agent"])
async def get_device_telemetry(
    device_id: int,
    current_user: User = Depends(admin_required),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """
    Get telemetry history for a specific agent device (admin only).
    """
    try:
        # Verify device exists
        device = db.query(Device).filter_by(id=device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Get telemetry snapshots
        total = db.query(Telemetry).filter_by(device_id=device_id).count()
        
        telemetry_snapshots = db.query(Telemetry)\
            .filter_by(device_id=device_id)\
            .order_by(Telemetry.collected_at.desc())\
            .offset(skip)\
            .limit(limit)\
            .all()
        
        return {
            "device_id": device_id,
            "device_uuid": device.device_uuid,
            "hostname": device.hostname,
            "data": [
                {
                    "id": t.id,
                    "collected_at": t.collected_at,
                    "metrics": json.loads(t.metrics) if t.metrics else None,
                    "sample_count": t.sample_count
                }
                for t in telemetry_snapshots
            ],
            "pagination": {
                "total": total,
                "skip": skip,
                "limit": limit,
                "total_pages": (total + limit - 1) // limit
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error fetching telemetry: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to fetch telemetry")


# ============================================================================
# END AGENT ENDPOINTS
# ============================================================================


# ---------------- Swagger Auth Support ----------------
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    schema = get_openapi(
        title="Secure Access API",
        version="1.0",
        description="Zero Trust Monitoring System Backend",
        routes=app.routes,
    )

    schema["components"]["securitySchemes"] = {
        "BearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"}
    }

    protected_endpoints = [
        "/profile",
        "/logs",
        "/logs/search",
        "/logs/enhanced",
        "/sessions",
        "/sessions/{session_id}",
        "/admin/dashboard",
        "/admin/profile",
        "/admin/logs",
        "/admin/logs/enhanced",
        "/admin/logs/export",
        "/admin/users",
        "/admin/users/all",
        "/admin/sessions",
        "/admin/sessions/{session_id}",
        "/users",
        "/users/{user_id}",
        "/admin/users/{user_id}/logs",
        "/users/{user_id}/logs",
        "/logout",
    ]
    
    for path in protected_endpoints:
        if path in schema["paths"]:
            for method in ["get", "post", "put", "delete"]:
                if method in schema["paths"][path]:
                    schema["paths"][path][method]["security"] = [{"BearerAuth": []}]

    app.openapi_schema = schema
    return app.openapi_schema

app.openapi = custom_openapi


if __name__ == "__main__":
    import uvicorn
    # Start on localhost:8000 for Google OAuth compatibility
    uvicorn.run(app, host="localhost", port=8000)
