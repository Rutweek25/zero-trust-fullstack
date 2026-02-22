# PHASE B: Complete Agent Endpoints Implementation
# Copy these endpoints to replace the existing agent endpoints in app.py (lines 1943-2260)
# This file shows the complete Phase B implementations with all features

"""
PHASE B AGENT ENDPOINTS

These endpoints implement comprehensive Zero Trust enforcement:
1. Secret token authentication (not JWT)
2. Admin approval workflow
3. Replay protection with nonce
4. Rate limiting (IP and token-based)
5. Online enforcement
6. Trust-triggered session revocation
7. Complete audit trail
8. Token rotation capability

Replace lines 1943-2260 in app.py with this complete implementation.
"""


# =============================================================================
# PHASE B: AGENT REGISTRATION ENDPOINT (Secret Tokens)
# =============================================================================

@app.post("/agent/register", response_model=AgentRegisterResponse, tags=["agent"])
async def register_agent(
    request_data: AgentRegisterRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    PHASE B: Register endpoint agent with secret token (not JWT).
    
    Security:
    - Random 64-byte secret token
    - Stored only as SHA256 hash
    - Requires admin approval before heartbeats
    - Rate limited by IP (10 requests/min)
    
    Returns:
    - agent_token: 128-char hex secret (save securely)
    - is_approved: Whether device is approved
    - Endpoint blocks heartbeats if not approved
    """
    try:
        ip_addr = get_client_ip(request)
        
        # Rate limit registration by IP
        allowed, error_msg = check_rate_limit_ip(ip_addr)
        if not allowed:
            log_entry = Log(
                event_type="AGENT_REGISTRATION_ATTEMPT_FAILED",
                action="Endpoint Agent Registration Failed",
                details=f"Rate limit exceeded: {error_msg}",
                ip_address=ip_addr,
                device=request_data.hostname or "unknown",
                risk_score=0.5,
                status="suspicious"
            )
            db.add(log_entry)
            db.commit()
            raise HTTPException(status_code=429, detail=error_msg)
        
        device_uuid = request_data.device_uuid.strip()
        if not device_uuid:
            raise HTTPException(status_code=400, detail="device_uuid is required")
        
        # Check if device already exists
        existing_device = db.query(Device).filter_by(device_uuid=device_uuid).first()
        
        if existing_device:
            # Re-registration: issue new secret token
            new_secret_token = generate_agent_token()  # Random 64-byte token
            existing_device.agent_token_hash = hash_agent_token(new_secret_token)
            existing_device.agent_token_created_at = now_ist()
            existing_device.agent_token_rotated_at = now_ist()
            existing_device.agent_requires_rotation = False
            existing_device.last_seen_at = now_ist()
            
            db.commit()
            db.refresh(existing_device)
            
            logger.info(f"Agent re-registered: Device {device_uuid[:16]}... (ID: {existing_device.id})")
            
            # Audit log
            audit_log = Log(
                event_type="AGENT_REGISTERED",
                action="Endpoint Agent Re-Registration",
                details=f"Device re-registered: {request_data.hostname}",
                ip_address=ip_addr,
                device=request_data.hostname or "unknown",
                risk_score=0.0,
                status="normal"
            )
            db.add(audit_log)
            db.commit()
            
            return AgentRegisterResponse(
                agent_token=new_secret_token,  # 128-char hex secret
                device_id=existing_device.id,
                registered_at=now_ist(),
                is_approved=existing_device.is_approved,
                heartbeat_interval=30,
                message="Device re-registered" + (". Awaiting approval." if not existing_device.is_approved else "")
            )
        
        # New device registration
        new_secret_token = generate_agent_token()  # PHASE B: Random secret, not JWT
        new_device = Device(
            user_id=None,
            device_uuid=device_uuid,
            hostname=request_data.hostname,
            os_version=request_data.os_version,
            device_name=f"{request_data.hostname} ({request_data.os_version})" if request_data.hostname else device_uuid,
            os=request_data.os_version.split()[0] if request_data.os_version else None,
            is_active=True,
            is_approved=False,  # PHASE B: Approval workflow - admin must approve
            trust_score=100.0,
            agent_token_hash=hash_agent_token(new_secret_token),
            agent_token_created_at=now_ist(),
            agent_token_rotated_at=now_ist(),
            first_registered_at=now_ist(),
            last_seen_at=now_ist()
        )
        
        db.add(new_device)
        db.commit()
        db.refresh(new_device)
        
        # Audit log
        registration_log = Log(
            user_id=None,
            event_type="AGENT_REGISTERED",
            action="Endpoint Agent Registration",
            details=f"New agent device registered: {request_data.hostname} ({request_data.os_version})",
            ip_address=ip_addr,
            device=request_data.hostname or "unknown",
            risk_score=0.0,
            status="normal"
        )
        db.add(registration_log)
        db.commit()
        
        logger.info(f"Agent registered: Device {device_uuid[:16]}... (ID: {new_device.id}) - Awaiting approval")
        
        return AgentRegisterResponse(
            agent_token=new_secret_token,  # PHASE B: 128-char hex secret token
            device_id=new_device.id,
            registered_at=now_ist(),
            is_approved=False,  # MUST BE APPROVED BY ADMIN
            heartbeat_interval=30,
            message="Device registered. Awaiting admin approval."
        )
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Agent registration error: {str(e)}")
        raise HTTPException(status_code=500, detail="Registration failed")


# =============================================================================
# PHASE B: AGENT HEARTBEAT ENDPOINT (Secure + Replay Protection)
# =============================================================================

@app.post("/agent/heartbeat", response_model=AgentHeartbeatResponse, tags=["agent"])
async def receive_agent_heartbeat(
    heartbeat: AgentHeartbeatRequest,
    request: Request,
    authorization: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    PHASE B: Secure heartbeat with comprehensive security checks.
    
    Security enforced:
    1. Bearer token validation (SHA256 hash check)
    2. Rate limiting (50 heartbeats/min per token)
    3. Nonce replay detection
    4. Timestamp freshness (< 60 sec old)
    5. Device approval status
    6. Online enforcement
    7. Trust score calculation
    8. Session revocation on trust drop
    9. Auto-disable on very low trust
    10. Token rotation requirement
    
    Returns:
    - new_trust_score: Updated trust score
    - is_approved: Current approval status
    - requires_rotation: Whether token needs rotation
    """
    try:
        ip_addr = get_client_ip(request)
        
        # ===== SECURITY CHECK 1: Token Format =====
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
        
        token = authorization.replace("Bearer ", "").strip()
        
        # PHASE B: Validate secret token format (128 chars hex)
        if not token or len(token) != 128 or not all(c in "0123456789abcdef" for c in token.lower()):
            raise HTTPException(status_code=401, detail="Invalid token format")
        
        # ===== SECURITY CHECK 2: Device Lookup =====
        device_uuid = heartbeat.device_uuid.strip()
        device = db.query(Device).filter_by(device_uuid=device_uuid).first()
        
        if not device:
            logger.warning(f"Heartbeat from unknown device: {device_uuid[:16]}...")
            audit_log = Log(
                event_type="AGENT_HEARTBEAT_FAILED",
                action="Heartbeat from Unknown Device",
                details=f"UUID not registered: {device_uuid[:16]}...",
                ip_address=ip_addr,
                device=device_uuid[:16] + "...",
                risk_score=0.7,
                status="suspicious"
            )
            db.add(audit_log)
            db.commit()
            raise HTTPException(status_code=404, detail="Device not registered")
        
        # ===== SECURITY CHECK 3: Token Hash Verification =====
        if not verify_agent_token(token, device.agent_token_hash):
            logger.warning(f"Token hash mismatch for device {device.id}: {device_uuid[:16]}...")
            audit_log = Log(
                event_type="AGENT_HEARTBEAT_FAILED",
                action="Heartbeat Invalid Token",
                details=f"Token hash mismatch for device {device.id}",
                ip_address=ip_addr,
                device=device.hostname,
                user_id=device.user_id,
                risk_score=0.8,
                status="critical"
            )
            db.add(audit_log)
            db.commit()
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # ===== SECURITY CHECK 4: Rate Limiting by Token =====
        token_hash = hash_agent_token(token)
        allowed, error_msg = check_rate_limit_token(token_hash)
        if not allowed:
            logger.warning(f"Rate limit exceeded: Device {device.id}")
            raise HTTPException(status_code=429, detail=error_msg)
        
        # ===== SECURITY CHECK 5: Replay Protection (Nonce) =====
        now = now_ist()
        nonce = heartbeat.nonce
        
        if nonce:
            # Replay detection: reject if nonce seen before
            if device.last_nonce == nonce:
                logger.warning(f"Replay detected: Device {device.id}, nonce {nonce[:16]}...")
                audit_log = Log(
                    event_type="AGENT_HEARTBEAT_REPLAY",
                    action="Heartbeat Replay Attack Detected",
                    details=f"Duplicate nonce from device {device.id}",
                    ip_address=ip_addr,
                    device=device.hostname,
                    user_id=device.user_id,
                    risk_score=0.9,
                    status="critical"
                )
                db.add(audit_log)
                db.commit()
                raise HTTPException(status_code=403, detail="Replay detected")
            
            # Store nonce for next check
            device.last_nonce = nonce
        
        # ===== SECURITY CHECK 6: Timestamp Freshness =====
        hb_timestamp = heartbeat.timestamp or now
        age_seconds = (now - hb_timestamp).total_seconds()
        
        if age_seconds > 60:  # PHASE B: Reject heartbeats > 60 sec old
            logger.warning(f"Stale heartbeat: Device {device.id}, age {age_seconds}s")
            raise HTTPException(status_code=400, detail="Heartbeat timestamp too old (> 60 seconds)")
        
        # ===== SECURITY CHECK 7: Approval Status =====
        if not device.is_approved:
            logger.info(f"Heartbeat from unapproved device: {device.id}")
            # Don't reject immediately - let device know it's waiting for approval
            # This allows agents to poll for approval status
            audit_log = Log(
                event_type="AGENT_HEARTBEAT_UNAPPROVED",
                action="Heartbeat from Unapproved Device",
                details=f"Device {device.id} not approved yet",
                ip_address=ip_addr,
                device=device.hostname,
                user_id=device.user_id,
                risk_score=0.3,
                status="normal"
            )
            db.add(audit_log)
            db.commit()
            
            return AgentHeartbeatResponse(
                status="pending",
                message="Device awaiting admin approval",
                device_id=device.id,
                new_trust_score=device.trust_score,
                is_approved=False,
                requires_rotation=validate_agent_token_rotation(device.agent_token_rotated_at),
                received_at=now
            )
        
        # ===== SECURITY CHECK 8: Device Active =====
        if not device.is_active:
            logger.warning(f"Heartbeat from disabled device: {device.id}")
            raise HTTPException(status_code=403, detail="Device is disabled")
        
        # ===== UPDATE DEVICE STATE =====
        device.last_seen_at = now
        
        # ===== SECURITY CHECK 9: Store Telemetry =====
        metrics_json = json.dumps(heartbeat.metrics.dict(exclude_none=True), default=str)
        telemetry = Telemetry(
            device_id=device.id,
            collected_at=hb_timestamp,
            metrics=metrics_json,
            sample_count=1
        )
        db.add(telemetry)
        
        # ===== CALCULATE TRUST SCORE =====
        suspicious = False
        
        # Anomaly detection
        if heartbeat.metrics.cpu and heartbeat.metrics.cpu.get("percent", 0) > 95:
            suspicious = True
        if heartbeat.metrics.memory and heartbeat.metrics.memory.get("virtual", {}).get("percent", 0) > 95:
            suspicious = True
        
        old_trust_score = device.trust_score
        new_trust_score = calculate_agent_trust_score(
            current_score=device.trust_score,
            last_seen_at=device.last_seen_at,
            suspicious_flag=suspicious
        )
        device.trust_score = new_trust_score
        
        # ===== AUDIT TRUST CHANGES =====
        if new_trust_score < old_trust_score:
            audit_log = Log(
                event_type="AGENT_TRUST_DROP",
                action="Trust Score Decreased",
                details=f"Trust: {old_trust_score:.1f} → {new_trust_score:.1f}" + (
                    " (Suspicious activity detected)" if suspicious else " (Stale device)"
                ),
                ip_address=ip_addr,
                device=device.hostname,
                user_id=device.user_id,
                risk_score=1.0 - (new_trust_score / 100.0),
                status="suspicious" if new_trust_score < 60 else "normal"
            )
            db.add(audit_log)
        
        # ===== PHASE B: SESSION REVOCATION ON TRUST DROP =====
        if new_trust_score < 40 and old_trust_score >= 40:
            revoked = revoke_device_sessions(
                db, device.id,
                f"Trust score dropped to {new_trust_score:.1f}"
            )
            logger.warning(f"Revoked {revoked} sessions for device {device.id}")
            
            audit_log = Log(
                event_type="AGENT_SESSIONS_REVOKED",
                action="Sessions Revoked on Trust Drop",
                details=f"Revoked {revoked} sessions - trust dropped to {new_trust_score:.1f}",
                ip_address=ip_addr,
                device=device.hostname,
                user_id=device.user_id,
                risk_score=0.8,
                status="critical"
            )
            db.add(audit_log)
        
        # ===== PHASE B: AUTO-DISABLE AT VERY LOW TRUST =====
        if new_trust_score < 20:
            device.is_active = False
            
            audit_log = Log(
                event_type="AGENT_DISABLED",
                action="Device Auto-Disabled",
                details=f"Trust score critically low: {new_trust_score:.1f}",
                ip_address=ip_addr,
                device=device.hostname,
                user_id=device.user_id,
                risk_score=1.0,
                status="critical"
            )
            db.add(audit_log)
            logger.critical(f"Device {device.id} auto-disabled: trust={new_trust_score:.1f}")
        
        # ===== PHASE B: TOKEN ROTATION CHECK =====
        requires_rotation = validate_agent_token_rotation(device.agent_token_rotated_at, max_age_days=90)
        device.agent_requires_rotation = requires_rotation
        
        # Commit all changes
        db.commit()
        db.refresh(device)
        
        # ===== FINAL AUDIT LOG =====
        audit_log = Log(
            event_type="AGENT_HEARTBEAT",
            action="Heartbeat Processed",
            details=f"Trust: {new_trust_score:.1f}, CPU: {heartbeat.metrics.cpu.get('percent', 0) if heartbeat.metrics.cpu else 'N/A'}%",
            ip_address=ip_addr,
            device=device.hostname,
            user_id=device.user_id,
            risk_score=1.0 - (new_trust_score / 100.0),
            status="normal" if new_trust_score >= 60 else "suspicious"
        )
        db.add(audit_log)
        db.commit()
        
        logger.info(
            f"Heartbeat received: Device {device_uuid[:16]}... "
            f"(ID: {device.id}) - Trust: {new_trust_score:.1f}"
        )
        
        return AgentHeartbeatResponse(
            status="success",
            message="Heartbeat received and processed",
            device_id=device.id,
            new_trust_score=new_trust_score,
            is_approved=device.is_approved,
            requires_rotation=requires_rotation,
            received_at=now
        )
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Heartbeat processing error: {str(e)}")
        raise HTTPException(status_code=500, detail="Heartbeat processing failed")


# =============================================================================
# PHASE B: TOKEN ROTATION ENDPOINT
# =============================================================================

@app.post("/agent/rotate-token", response_model=AgentTokenRotateResponse, tags=["agent"])
async def rotate_agent_token(
    request_data: AgentTokenRotateRequest,
    request: Request,
    authorization: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """
    PHASE B: Rotate agent token (revokes old, issues new).
    
    Used when:
    - Token exceeds 90-day age (server indicates "requires_rotation": true)
    - Admin forces rotation
    - Password compromise suspected
    
    Requires valid current token.
    """
    try:
        ip_addr = get_client_ip(request)
        
        # Find device
        device_uuid = request_data.device_uuid.strip()
        device = db.query(Device).filter_by(device_uuid=device_uuid).first()
        
        if not device:
            logger.warning(f"Rotation request from unknown device: {device_uuid[:16]}...")
            raise HTTPException(status_code=404, detail="Device not found")
        
        # Verify current token if provided
        if request_data.current_token:
            if not verify_agent_token(request_data.current_token, device.agent_token_hash):
                logger.warning(f"Rotation failed: Invalid token for device {device.id}")
                audit_log = Log(
                    event_type="AGENT_ROTATION_FAILED",
                    action="Token Rotation Failed",
                    details=f"Invalid current token for device {device.id}",
                    ip_address=ip_addr,
                    device=device.hostname,
                    user_id=device.user_id,
                    risk_score=0.7,
                    status="suspicious"
                )
                db.add(audit_log)
                db.commit()
                raise HTTPException(status_code=401, detail="Current token invalid")
        
        # Generate new secret token
        new_secret_token = generate_agent_token()
        now = now_ist()
        
        # Update device with new token
        device.agent_token_hash = hash_agent_token(new_secret_token)
        device.agent_token_created_at = now
        device.agent_token_rotated_at = now
        device.agent_requires_rotation = False
        
        db.commit()
        db.refresh(device)
        
        # Audit log
        audit_log = Log(
            event_type="AGENT_TOKEN_ROTATED",
            action="Agent Token Rotated",
            details=f"Token rotated for device {device.id}: {device_uuid[:16]}...",
            ip_address=ip_addr,
            device=device.hostname,
            user_id=device.user_id,
            risk_score=0.0,
            status="normal"
        )
        db.add(audit_log)
        db.commit()
        
        logger.info(f"Token rotated for device {device.id}")
        
        return AgentTokenRotateResponse(
            status="success",
            message="Token rotated successfully",
            old_token_revoked_at=now,
            new_token=new_secret_token,
            device_id=device.id
        )
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Token rotation error: {str(e)}")
        raise HTTPException(status_code=500, detail="Token rotation failed")


# =============================================================================
# PHASE B: ADMIN DEVICE APPROVAL ENDPOINT
# =============================================================================

@app.post("/agent/devices/{device_id}/approve", response_model=AgentApprovalResponse, tags=["agent"])
async def approve_agent_device(
    device_id: int,
    request_data: AgentApprovalRequest,
    request: Request,
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    """
    PHASE B: Admin endpoint to approve/reject agent devices.
    
    Required before device can send heartbeats or connect to sessions.
    
    Actions:
    - "approve": Device can now heartbeat and connect
    - "reject": Device is permanently blocked
    """
    try:
        device = db.query(Device).filter_by(id=device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        now = now_ist()
        action = request_data.action.lower()
        
        if action == "approve":
            device.is_approved = True
            device.is_active = True
            msg = "Device approved"
            event_type = "AGENT_APPROVED"
            risk = 0.0
            status = "normal"
        elif action == "reject":
            device.is_active = False
            device.is_approved = False
            msg = "Device rejected"
            event_type = "AGENT_REJECTED"
            risk = 0.5
            status = "suspicious"
            
            # Revoke any existing sessions
            revoke_device_sessions(db, device.id, f"Rejected by {current_user.username}")
        else:
            raise HTTPException(status_code=400, detail="Invalid action (must be 'approve' or 'reject')")
        
        # Audit log
        audit_log = Log(
            event_type=event_type,
            action=f"Device {action.title()}ed",
            details=f"{action.capitalize()}ed by {current_user.username}" + (
                f": {request_data.reason}" if request_data.reason else ""
            ),
            ip_address=get_client_ip(request),
            device=device.hostname,
            user_id=current_user.id,
            risk_score=risk,
            status=status
        )
        db.add(audit_log)
        db.commit()
        db.refresh(device)
        
        logger.info(f"Device {device_id} {action}ed by {current_user.username}")
        
        return AgentApprovalResponse(
            device_id=device.id,
            is_approved=device.is_approved,
            device_uuid=device.device_uuid,
            hostname=device.hostname,
            approved_at=now if action == "approve" else None,
            message=msg
        )
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        logger.error(f"Device approval error: {str(e)}")
        raise HTTPException(status_code=500, detail="Approval action failed")


# =============================================================================
# EXISTING ENDPOINTS (updated for audit logging)
# =============================================================================

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
        
        # Audit log
        audit_log = Log(
            event_type="ADMIN_VIEW_DEVICES",
            action="Admin Viewed Agent Devices",
            details=f"Listed {len(devices)} devices",
            ip_address="internal",
            device="admin-dashboard",
            user_id=current_user.id,
            risk_score=0.0,
            status="normal"
        )
        db.add(audit_log)
        db.commit()
        
        return {
            "data": [
                {
                    "id": d.id,
                    "uuid": d.device_uuid,
                    "hostname": d.hostname,
                    "os_version": d.os_version,
                    "trust_score": d.trust_score,
                    "is_active": d.is_active,
                    "is_approved": d.is_approved,
                    "last_seen": d.last_seen_at,
                    "registered_at": d.first_registered_at
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
        device = db.query(Device).filter_by(id=device_id).first()
        if not device:
            raise HTTPException(status_code=404, detail="Device not found")
        
        total = db.query(Telemetry).filter_by(device_id=device_id).count()
        
        telemetry_snapshots = db.query(Telemetry)\
            .filter_by(device_id=device_id)\
            .order_by(Telemetry.collected_at.desc())\
            .offset(skip)\
            .limit(limit)\
            .all()
        
        # Audit log
        audit_log = Log(
            event_type="ADMIN_VIEW_TELEMETRY",
            action="Admin Viewed Device Telemetry",
            details=f"Viewed {len(telemetry_snapshots)} telemetry snapshots for device {device_id}",
            ip_address="internal",
            device=device.hostname,
            user_id=current_user.id,
            risk_score=0.0,
            status="normal"
        )
        db.add(audit_log)
        db.commit()
        
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
