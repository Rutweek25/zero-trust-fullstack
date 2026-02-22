from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Boolean, Float
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime
from time_utils import now_ist
import uuid

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    name = Column(String, nullable=False)
    company_email = Column(String, unique=True, index=True, nullable=True)
    personal_email = Column(String, unique=True, index=True, nullable=True)
    password_hash = Column(String, nullable=True)
    role = Column(String, default="user", nullable=False)  # user, admin, superadmin

    # Auth provider fields
    auth_provider = Column(String, default="local", nullable=False, index=True)
    microsoft_id = Column(String, unique=True, index=True, nullable=True)
    
    # Profile fields
    profile_photo = Column(String, nullable=True)
    status = Column(String, default="active", nullable=False)  # active, inactive, locked
    created_at = Column(DateTime(timezone=True), default=now_ist, nullable=False)
    
    # PHASE 1: Enhanced tracking fields
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    last_logout_at = Column(DateTime(timezone=True), nullable=True)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    account_locked = Column(Boolean, default=False, nullable=False)
    locked_at = Column(DateTime(timezone=True), nullable=True)

    # PHASE 2: Security intelligence fields
    last_login_country = Column(String, nullable=True)
    login_ip_history = Column(Text, nullable=True)  # JSON array of last 10 IPs
    
    # Legacy field for backward compatibility
    last_login = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    devices = relationship("Device", back_populates="user", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User(id={self.id}, username={self.username}, role={self.role})>"


class Session(Base):
    """Track user login sessions with device and location info"""
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String, unique=True, index=True, nullable=False, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True, index=True)  # Link to device
    
    # Network info
    ip_address = Column(String, nullable=False, index=True)
    country = Column(String, nullable=True)
    city = Column(String, nullable=True)
    
    # GPS Coordinates (from browser geolocation)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    
    # Device info
    browser = Column(String, nullable=True)
    os = Column(String, nullable=True)
    device = Column(String, nullable=True)
    user_agent = Column(Text, nullable=True)
    
    # Security & Risk Assessment
    risk_score = Column(Float, default=0.0, nullable=False)  # 0.0 to 1.0
    status = Column(String, default="normal", nullable=False, index=True)  # normal, suspicious, critical
    risk_factors = Column(Text, nullable=True)  # JSON array of detected risk factors
    
    # Session timing
    login_at = Column(DateTime(timezone=True), default=now_ist, nullable=False, index=True)
    logout_at = Column(DateTime(timezone=True), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    
    def __repr__(self):
        return f"<Session(id={self.id}, user_id={self.user_id}, ip={self.ip_address}, active={self.is_active})>"


class Log(Base):
    """Enhanced logging with event types, risk scoring, and location tracking"""
    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    
    # Event classification
    event_type = Column(String, nullable=False, index=True)  # LOGIN_SUCCESS, LOGIN_FAILED, LOGOUT, etc.
    action = Column(String, nullable=False, index=True)  # Human-readable action
    details = Column(Text, default="")
    
    # Network & Location
    ip_address = Column(String, nullable=False, index=True)
    location = Column(String, nullable=True)  # "City, Country"
    
    # Device info
    device = Column(String, nullable=False, index=True)
    browser = Column(String, nullable=True)
    os = Column(String, nullable=True)
    
    # Risk assessment
    risk_score = Column(Float, default=0.0, nullable=False)  # 0.0 to 1.0
    status = Column(String, default="normal", nullable=False, index=True)  # normal, suspicious, critical
    
    # Timing
    timestamp = Column(DateTime(timezone=True), default=now_ist, nullable=False, index=True)
    
    # Legacy field for backward compatibility
    time = Column(DateTime(timezone=True), default=now_ist, nullable=False, index=True)
    ip = Column(String, nullable=True)  # Legacy field
    
    def __repr__(self):
        return f"<Log(id={self.id}, user_id={self.user_id}, event_type={self.event_type}, timestamp={self.timestamp})>"


class LockUnlockRequest(Base):
    """Track lock/unlock requests from admins that need superadmin approval"""
    __tablename__ = "lock_unlock_requests"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)  # Target user
    requested_by_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)  # Admin who made request
    
    action = Column(String, nullable=False)  # "lock" or "unlock"
    reason = Column(Text, nullable=True)  # Admin's reason for request
    risk_score = Column(Float, nullable=True)  # Current risk score of target user
    user_details = Column(Text, nullable=True)  # JSON with user info at time of request
    
    # Request status
    status = Column(String, default="pending", nullable=False, index=True)  # pending, approved, rejected
    
    # Approval tracking
    reviewed_by_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # Superadmin who reviewed
    reviewed_at = Column(DateTime(timezone=True), nullable=True)
    review_comment = Column(Text, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), default=now_ist, nullable=False, index=True)
    
    def __repr__(self):
        return f"<LockUnlockRequest(id={self.id}, user_id={self.user_id}, action={self.action}, status={self.status})>"


class Device(Base):
    """Track registered devices for zero trust device authentication"""
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True, index=True)  # Nullable for agent devices
    
    # Device identification
    device_uuid = Column(String(128), unique=True, index=True, nullable=False)
    device_name = Column(String(255), nullable=True)  # Legacy - web devices had this
    hostname = Column(String(255), nullable=True)  # For endpoint agents
    os = Column(String(100), nullable=True)
    os_version = Column(String(100), nullable=True)  # Specific OS version for agents
    
    # Tracking
    first_registered_at = Column(DateTime(timezone=True), default=now_ist, nullable=False)
    last_seen_at = Column(DateTime(timezone=True), default=now_ist, nullable=False, index=True)
    
    # Trust management
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    trust_score = Column(Float, default=100.0, nullable=False)  # 0.0 to 100.0
    
    # PHASE B: Agent authentication hardening (secret token instead of JWT)
    # Secret token system: random 64-byte token, stored as SHA256 hash
    agent_token_hash = Column(String(256), nullable=True, index=True)  # SHA256 hash of secret token
    agent_token_created_at = Column(DateTime(timezone=True), nullable=True)  # When token was issued
    agent_token_rotated_at = Column(DateTime(timezone=True), nullable=True)  # Last rotation timestamp
    agent_requires_rotation = Column(Boolean, default=False, nullable=False)  # Force immediate rotation
    
    # PHASE B: Registration approval workflow
    is_approved = Column(Boolean, default=False, nullable=False, index=True)  # Admin must approve agent
    
    # PHASE B: Replay protection
    last_nonce = Column(String(64), nullable=True)  # Last nonce received to prevent replay
    
    # Relationships
    user = relationship("User", back_populates="devices")
    telemetry_snapshots = relationship("Telemetry", back_populates="device", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<Device(id={self.id}, user_id={self.user_id}, device_uuid={self.device_uuid}, trust_score={self.trust_score})>"


class Telemetry(Base):
    """Store agent heartbeat telemetry snapshots"""
    __tablename__ = "telemetry"

    id = Column(Integer, primary_key=True, index=True)
    device_id = Column(Integer, ForeignKey("devices.id", ondelete="CASCADE"), nullable=False, index=True)
    
    # Timestamp of collection
    collected_at = Column(DateTime(timezone=True), default=now_ist, nullable=False, index=True)
    
    # System metrics (stored as serialized JSON for flexibility)
    metrics = Column(Text, nullable=True)  # JSON: {cpu, memory, disk, processes, network, users, usb_devices}
    
    # Data quality
    sample_count = Column(Integer, default=1, nullable=False)  # For aggregated data
    
    # Relationships
    device = relationship("Device", back_populates="telemetry_snapshots")
    
    def __repr__(self):
        return f"<Telemetry(id={self.id}, device_id={self.device_id}, collected_at={self.collected_at})>"
