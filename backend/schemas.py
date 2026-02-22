from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional, Any
import json

class UserCreate(BaseModel):
    username: str
    name: str
    company_email: EmailStr
    personal_email: EmailStr
    password: str
    role: str = "user"   # default user, but will be forced to 'user'

class UserLogin(BaseModel):
    username: str  # now an email
    password: str
    device_uuid: Optional[str] = None  # Optional - will auto-generate if not provided
    browser_location: Optional[dict[str, Any]] = None

class UserResponse(BaseModel):
    id: int
    username: str
    name: str
    company_email: Optional[str] = None
    personal_email: Optional[str] = None
    role: str
    auth_provider: Optional[str] = "local"
    microsoft_id: Optional[str] = None
    profile_photo: Optional[str] = None
    last_login: Optional[datetime] = None
    last_login_at: Optional[datetime] = None
    last_logout_at: Optional[datetime] = None
    failed_login_attempts: Optional[int] = 0
    account_locked: Optional[bool] = False
    last_login_country: Optional[str] = None
    login_ip_history: Optional[str] = None
    status: Optional[str] = "active"
    created_at: datetime
    
    class Config:
        from_attributes = True

# =============================================================================
# PHASE 1: Session Schemas
# =============================================================================

class SessionResponse(BaseModel):
    """Response model for session data"""
    id: int
    session_id: str
    user_id: int
    ip_address: str
    country: Optional[str]
    city: Optional[str]
    browser: Optional[str]
    os: Optional[str]
    device: Optional[str]
    login_at: datetime
    logout_at: Optional[datetime]
    is_active: bool
    
    class Config:
        from_attributes = True


class EnhancedSessionResponse(BaseModel):
    """Enhanced session response with geolocation and risk assessment"""
    id: int
    session_id: str
    user_id: int
    username: Optional[str] = None  # Joined from User table
    ip_address: str
    country: Optional[str]
    city: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    browser: Optional[str]
    os: Optional[str]
    device: Optional[str]
    user_agent: Optional[str]
    risk_score: float
    status: str  # normal, suspicious, critical
    risk_factors: Optional[str]  # JSON string of risk factors
    login_at: datetime
    logout_at: Optional[datetime]
    is_active: bool
    
    class Config:
        from_attributes = True

class SessionSummary(BaseModel):
    """Simplified session info for user display"""
    session_id: str
    device: str
    location: str
    login_at: datetime
    is_active: bool

# =============================================================================
# Legacy Log Schemas (kept for backward compatibility)
# =============================================================================

class LogCreate(BaseModel):
    """Schema for collecting logs from agents"""
    username: str  # will be resolved to user_id
    action: str
    details: str = ""
    ip: str
    device: str
    
    class Config:
        json_schema_extra = {
            "example": {
                "username": "john_doe",
                "action": "file_access",
                "details": "Accessed /etc/passwd",
                "ip": "192.168.1.100",
                "device": "LAPTOP-XYZ"
            }
        }

class LogResponse(BaseModel):
    id: int
    user_id: Optional[int]
    action: str
    details: str
    ip: str
    device: str
    time: datetime
    
    class Config:
        from_attributes = True

# =============================================================================
# PHASE 1: Enhanced Log Schemas
# =============================================================================

class EnhancedLogResponse(BaseModel):
    """Enhanced log response with all Phase 1 fields"""
    id: int
    user_id: Optional[int]
    event_type: str
    action: str
    details: str
    ip_address: str
    location: Optional[str]
    device: str
    browser: Optional[str]
    os: Optional[str]
    risk_score: float
    status: str
    timestamp: datetime
    
    class Config:
        from_attributes = True

# =============================================================================
# PHASE 3: Admin Monitoring Responses
# =============================================================================

class Pagination(BaseModel):
    total: int
    page: int
    limit: int
    total_pages: int

class AdminUserOut(UserResponse):
    active_session_count: int = 0

class AdminUsersResponse(BaseModel):
    data: list[AdminUserOut]
    pagination: Pagination

class AdminUserLogsResponse(BaseModel):
    user_id: int
    username: str
    role: str
    data: list[EnhancedLogResponse]
    pagination: Pagination

class AdminSessionsResponse(BaseModel):
    data: list[SessionResponse]
    pagination: Pagination


class LoginHistoryResponse(BaseModel):
    """Response model for admin login history with enhanced security data"""
    data: list[EnhancedSessionResponse]
    pagination: Pagination
    summary: dict[str, Any] = {}  # Summary statistics (total logins, suspicious percentage, etc.)

# =============================================================================
# Token Schemas
# =============================================================================

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    role: str
    username: str

class EnhancedTokenResponse(TokenResponse):
    """Token response with session info"""
    session_id: str
    device: str
    location: str


# =============================================================================
# Lock/Unlock Request Schemas
# =============================================================================

class LockUnlockRequestCreate(BaseModel):
    """Request to lock or unlock a user"""
    action: str  # "lock" or "unlock"
    reason: Optional[str] = None

class LockUnlockRequestResponse(BaseModel):
    """Response for lock/unlock request"""
    id: int
    user_id: int
    requested_by_id: int
    action: str
    reason: Optional[str]
    risk_score: Optional[float]
    user_details: Optional[str]
    status: str
    reviewed_by_id: Optional[int]
    reviewed_at: Optional[datetime]
    review_comment: Optional[str]
    created_at: datetime
    
    # Additional fields for frontend display
    target_username: Optional[str] = None
    requested_by_username: Optional[str] = None
    reviewed_by_username: Optional[str] = None
    
    class Config:
        from_attributes = True

class ReviewRequestAction(BaseModel):
    """Superadmin review action"""
    action: str  # "approve" or "reject"
    comment: Optional[str] = None

class PendingRequestsResponse(BaseModel):
    """Response for pending requests list"""
    data: list[LockUnlockRequestResponse]
    pagination: Pagination


# =============================================================================
# Device Registration Schemas
# =============================================================================

class DeviceRegister(BaseModel):
    """Request schema for device registration"""
    device_uuid: str
    device_name: str
    os: Optional[str] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "device_uuid": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6",
                "device_name": "iPhone 15 Pro - Safari",
                "os": "iOS 17.3"
            }
        }

class DeviceResponse(BaseModel):
    """Response schema for device registration"""
    id: int
    device_uuid: str
    device_name: str
    os: Optional[str]
    trust_score: float
    is_active: bool
    first_registered_at: datetime
    last_seen_at: datetime
    
    class Config:
        from_attributes = True


# =============================================================================
# Agent Endpoint Schemas
# =============================================================================

class AgentSystemInfo(BaseModel):
    """System information from endpoint agent"""
    mac_address: Optional[str] = None
    cpu_model: Optional[str] = None
    total_memory_gb: Optional[float] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "mac_address": "00:11:22:33:44:55",
                "cpu_model": "Intel Core i7-10700K",
                "total_memory_gb": 16.0
            }
        }


class AgentRegisterRequest(BaseModel):
    """Request to register endpoint agent device"""
    device_uuid: str
    hostname: str
    os_version: str
    system_info: Optional[AgentSystemInfo] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "device_uuid": "a3f5b2c1d4e7f9a8b3c5d7e9f1a3b5c7",
                "hostname": "JOHN-PC",
                "os_version": "Windows 10 (Build 19045)",
                "system_info": {
                    "mac_address": "00:11:22:33:44:55",
                    "cpu_model": "Intel Core i7-10700K",
                    "total_memory_gb": 16.0
                }
            }
        }


class AgentRegisterResponse(BaseModel):
    """Response after agent registration - PHASE B: Secret token (not JWT)"""
    agent_token: str  # 128-character hex secret token
    device_id: int
    registered_at: datetime
    is_approved: bool
    heartbeat_interval: int = 30
    message: str = "Device registered. Awaiting admin approval."
    
    class Config:
        json_schema_extra = {
            "example": {
                "agent_token": "a7f3c9e2b1d4f6a8c0e1f2d3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a3f5c9e2b1d4f6a8c0e1f2d3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1",
                "device_id": 42,
                "registered_at": "2024-01-15T10:30:45.123456+00:00",
                "is_approved": False,
                "heartbeat_interval": 30,
                "message": "Device registered. Awaiting admin approval."
            }
        }


class TelemetryMetrics(BaseModel):
    """System telemetry metrics from agent"""
    cpu: Optional[dict[str, Any]] = None
    memory: Optional[dict[str, Any]] = None
    disk: Optional[dict[str, Any]] = None
    processes: Optional[dict[str, Any]] = None
    network: Optional[dict[str, Any]] = None
    logged_in_users: Optional[list[dict[str, Any]]] = None
    usb_devices: Optional[list[dict[str, Any]]] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "cpu": {"percent": 25.5, "per_cpu": [20, 30, 25, 26]},
                "memory": {"virtual": {"used_mb": 8192, "percent": 50}},
                "disk": {"disks": [{"device": "C:", "used_gb": 250}]},
                "processes": {"total": 150, "running": 145},
                "network": {"connections": {"ESTABLISHED": 25}},
                "logged_in_users": [{"name": "john", "terminal": "pts/0"}],
                "usb_devices": [{"name": "Kingston DataTraveler"}]
            }
        }


class AgentHeartbeatRequest(BaseModel):
    """Heartbeat data from endpoint agent - PHASE B: Includes replay protection nonce"""
    device_uuid: str
    metrics: TelemetryMetrics
    timestamp: Optional[datetime] = None
    nonce: Optional[str] = None  # PHASE B: 16-byte random hex for replay protection
    
    class Config:
        json_schema_extra = {
            "example": {
                "device_uuid": "a3f5b2c1d4e7f9a8b3c5d7e9f1a3b5c7",
                "metrics": {
                    "cpu": {"percent": 25.5},
                    "memory": {"virtual": {"percent": 50.0}}
                },
                "timestamp": "2024-01-15T10:30:45.123456+00:00",
                "nonce": "a7f3c9e2b1d4f6a8"
            }
        }


class AgentHeartbeatResponse(BaseModel):
    """Response to heartbeat - PHASE B: Includes approval and rotation status"""
    status: str = "success"
    message: str = "Heartbeat received"
    device_id: int
    new_trust_score: float
    is_approved: bool  # PHASE B: Admin approval status
    requires_rotation: bool = False  # PHASE B: Force token rotation if True
    received_at: datetime
    
    class Config:
        json_schema_extra = {
            "example": {
                "status": "success",
                "message": "Heartbeat received",
                "device_id": 42,
                "new_trust_score": 95.0,
                "is_approved": True,
                "requires_rotation": False,
                "received_at": "2024-01-15T10:30:45.123456+00:00"
            }
        }


class TelemetryResponse(BaseModel):
    """Response model for telemetry data"""
    id: int
    device_id: int
    collected_at: datetime
    metrics: Optional[dict] = None
    
    class Config:
        from_attributes = True

# =============================================================================
# PHASE B: TOKEN ROTATION & DEVICE APPROVAL SCHEMAS
# =============================================================================

class AgentTokenRotateRequest(BaseModel):
    """Request to rotate agent token"""
    device_uuid: str
    current_token: Optional[str] = None  # Optional - some agents may just provide UUID
    
    class Config:
        json_schema_extra = {
            "example": {
                "device_uuid": "a3f5b2c1d4e7f9a8b3c5d7e9f1a3b5c7",
                "current_token": "a7f3c9e2b1d4f6a8c0e1f2d3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a3f5c9e2b1d4f6a8c0e1f2d3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1"
            }
        }


class AgentTokenRotateResponse(BaseModel):
    """Response after token rotation"""
    status: str = "success"
    message: str = "Token rotated successfully"
    old_token_revoked_at: datetime
    new_token: str  # New 128-character hex secret
    device_id: int
    
    class Config:
        json_schema_extra = {
            "example": {
                "status": "success",
                "message": "Token rotated successfully",
                "old_token_revoked_at": "2024-01-15T10:30:45.123456+00:00",
                "new_token": "b8f4d0e3c2e5f7a9d1f0e2d4c5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4d0e3c2e5f7a9d1f0e2d4c5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2",
                "device_id": 42
            }
        }


class AgentApprovalRequest(BaseModel):
    """Admin request to approve or reject device"""
    action: str  # "approve" or "reject"
    reason: Optional[str] = None
    
    class Config:
        json_schema_extra = {
            "example": {
                "action": "approve",
                "reason": "Device verified on-site"
            }
        }


class AgentApprovalResponse(BaseModel):
    """Response after device approval"""
    device_id: int
    is_approved: bool
    device_uuid: str
    hostname: str
    approved_at: Optional[datetime] = None
    message: str
    
    class Config:
        json_schema_extra = {
            "example": {
                "device_id": 42,
                "is_approved": True,
                "device_uuid": "a3f5b2c1d4e7f9a8b3c5d7e9f1a3b5c7",
                "hostname": "JOHN-PC",
                "approved_at": "2024-01-15T10:30:45.123456+00:00",
                "message": "Device approved"
            }
        }