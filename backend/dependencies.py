from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from auth import SECRET_KEY, ALGORITHM
from time_utils import now_ist, ensure_ist
from database import SessionLocal
from sqlalchemy.orm import Session
import models

# Use HTTP Bearer Token — NOT OAuth2
security = HTTPBearer()  


def get_db():
    """Database session dependency"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Validate user based on JWT token WITH device binding
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), 
                     db: Session = Depends(get_db)):
    """
    Extract and validate JWT token with full zero-trust enforcement.
    
    Optimized Validation Pipeline:
    1. Decode JWT and extract user_id, device_id, session_id
    2. Query session (with user_id filter for DB-level validation)
    3. Verify session is active
    4. Check device-session binding (before device query - fail fast)
    5. Query device (with user_id + device_id filters for atomic validation)
    6. Verify device is active and trusted
    7. Query user (only used for return value)
    
    This provides:
    ✓ Token validation (JWT signature)
    ✓ Session validation (revocation capability)
    ✓ Session expiry validation (server-enforced)
    ✓ Device-session binding (prevents token replay)
    ✓ Device validation (device-bound tokens)
    ✓ Trust validation (device trust scoring)
    ✓ Atomic queries (filters at DB level, not in-memory)
    
    Returns authenticated user if all checks pass.
    
    Raises:
    - 401: Invalid token, session not found/revoked, or user not found
    - 403: Device issues or permission denied
    """
    token = credentials.credentials  # extract token from Authorization header

    try:
        # Decode JWT payload
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id_str = payload.get("sub")
        device_id = payload.get("device_id")
        session_id = payload.get("session_id")

        # Validate required fields in token
        if user_id_str is None or session_id is None:
            raise HTTPException(
                status_code=401, 
                detail="Invalid authentication credentials"
            )
        
        # device_id is optional (can be None for web-only logins without agent)
        
        # Convert user_id to integer
        try:
            user_id = int(user_id_str)
        except (ValueError, TypeError):
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")

        # =====================================================================
        # SESSION VALIDATION (Stateful session enforcement - Query with filters)
        # =====================================================================
        # Query session with user_id included in filter for DB-level atomic validation
        # This prevents session-user mismatch at the database level
        
        session = db.query(models.Session).filter(
            models.Session.session_id == session_id,
            models.Session.user_id == user_id
        ).first()

        if session is None:
            raise HTTPException(
                status_code=401,
                detail="Session not found"
            )

        # Server-side session expiration enforcement (in addition to JWT exp)
        from datetime import timezone
        if hasattr(session, 'expires_at') and session.expires_at:
            expires_at = ensure_ist(session.expires_at)
            if expires_at and expires_at < now_ist():
                raise HTTPException(
                    status_code=401,
                    detail="Session expired"
                )

        # Verify session is active (not revoked by admin/logout)
        if not session.is_active:
            raise HTTPException(
                status_code=401,
                detail="Session revoked"
            )

        # =====================================================================
        # DEVICE-SESSION BINDING CHECK (Optional - Only if device present)
        # =====================================================================
        # Check binding before querying device - only if device_id is present
        # This prevents token replay but allows web-only sessions without device
        
        if device_id is not None and session.device_id != device_id:
            raise HTTPException(
                status_code=403,
                detail="Session not bound to device"
            )

        # =====================================================================
        # DEVICE VALIDATION (Optional - Only if device present)
        # =====================================================================
        # Skip device validation for web-only logins without agent device
        # Device validation only required if device_id is present in token
        
        if device_id is not None:
            # Query device with both device_id AND user_id filters
            # Ensures device exists AND belongs to user in single query
            
            device = db.query(models.Device).filter(
                models.Device.id == device_id,
                models.Device.user_id == user_id
            ).first()

            if device is None:
                raise HTTPException(
                    status_code=401, 
                    detail="Device not found"
                )

            # Check if device is active
            if not device.is_active:
                raise HTTPException(
                    status_code=403, 
                    detail="Device has been deactivated"
                )

            # Check if device is approved (PHASE B)
            if not device.is_approved:
                raise HTTPException(
                    status_code=403,
                    detail="Device is not approved"
                )

            # PHASE B: Check if device is online (last_seen_at within 90 seconds)
            from datetime import timezone, timedelta
            if device.last_seen_at is None:
                raise HTTPException(
                    status_code=403,
                    detail="Device has never reported heartbeat"
                )

            last_seen_at = ensure_ist(device.last_seen_at)
            time_since_last_seen = now_ist() - last_seen_at
            if time_since_last_seen > timedelta(seconds=90):
                raise HTTPException(
                    status_code=403,
                    detail="Device is offline"
                )

            # Check if device is trusted
            if device.trust_score < 60:  # PHASE B: Raised threshold from 40 to 60
                raise HTTPException(
                    status_code=403, 
                    detail="Device trust score is too low"
                )

        # =====================================================================
        # USER RETRIEVAL (Final step - only needed to return user object)
        # =====================================================================
        # Query user to return authenticated user object
        # Session validation already confirms user exists
        
        user = db.query(models.User).filter(models.User.id == user_id).first()

        if user is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")

        # All validations passed - return authenticated user
        return user

    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except HTTPException:
        # Re-raise HTTPExceptions (validation failures)
        raise


# Admin access guard
def admin_required(current_user: models.User = Depends(get_current_user)):
    """Verify user is admin"""
    # Allow both 'admin' and 'superadmin' roles to access admin-only routes
    if current_user.role not in ("admin", "superadmin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user

