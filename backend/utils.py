"""
Utility functions for PHASE 1: Session Tracking & Geolocation
"""
import httpx
import json
import ipaddress
from user_agents import parse
from fastapi import Request
from typing import Optional, Dict, Tuple
from time_utils import now_ist, ensure_ist
import logging

logger = logging.getLogger(__name__)

# =============================================================================
# IP ADDRESS EXTRACTION
# =============================================================================

def get_client_ip(request: Request) -> str:
    """
    Extract client IP address from request, handling proxies and load balancers
    
    Priority order:
    1. X-Forwarded-For header (common with proxies)
    2. X-Real-IP header (nginx)
    3. request.client.host (direct connection)
    """
    # Check X-Forwarded-For header (can contain multiple IPs)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take the first IP (original client)
        return forwarded_for.split(",")[0].strip()
    
    # Check X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # Fallback to direct connection
    if request.client and request.client.host:
        return request.client.host
    
    return "unknown"


# =============================================================================
# USER AGENT PARSING
# =============================================================================

def parse_user_agent(user_agent_string: str) -> Dict[str, Optional[str]]:
    """
    Parse user agent string to extract browser, OS, and device information
    
    Returns:
        {
            "browser": "Chrome 120.0",
            "os": "Windows 10",
            "device": "PC",
            "full_string": "Mozilla/5.0..."
        }
    """
    try:
        ua = parse(user_agent_string)
        
        # Get browser info
        browser = f"{ua.browser.family} {ua.browser.version_string}" if ua.browser.family else "Unknown Browser"
        
        # Get OS info
        os = f"{ua.os.family} {ua.os.version_string}" if ua.os.family else "Unknown OS"
        
        # Get device type
        if ua.is_mobile:
            device = f"Mobile - {ua.device.family}" if ua.device.family else "Mobile"
        elif ua.is_tablet:
            device = f"Tablet - {ua.device.family}" if ua.device.family else "Tablet"
        elif ua.is_pc:
            device = "PC"
        elif ua.is_bot:
            device = f"Bot - {ua.device.family}" if ua.device.family else "Bot"
        else:
            device = "Unknown Device"
        
        return {
            "browser": browser,
            "os": os,
            "device": device,
            "full_string": user_agent_string
        }
    except Exception as e:
        logger.error(f"Error parsing user agent: {e}")
        return {
            "browser": "Unknown Browser",
            "os": "Unknown OS",
            "device": "Unknown Device",
            "full_string": user_agent_string
        }


def get_user_agent_info(request: Request) -> Dict[str, Optional[str]]:
    """Extract and parse user agent from request"""
    user_agent_string = request.headers.get("User-Agent", "Unknown")
    return parse_user_agent(user_agent_string)


# =============================================================================
# GEOLOCATION FROM IP
# =============================================================================

def _parse_float(value: object) -> Optional[float]:
    try:
        if value is None:
            return None
        return float(value)
    except Exception:
        return None


def _extract_browser_coordinates(
    browser_location: Optional[dict],
    request: Optional[Request] = None
) -> Tuple[Optional[float], Optional[float], Optional[str]]:
    if isinstance(browser_location, dict):
        lat = _parse_float(browser_location.get("latitude"))
        lon = _parse_float(browser_location.get("longitude"))
        status = browser_location.get("permission_status")
        if lat is not None and lon is not None:
            return lat, lon, status or "granted"

    if request is not None:
        lat = _parse_float(request.headers.get("X-User-Latitude"))
        lon = _parse_float(request.headers.get("X-User-Longitude"))
        if lat is not None and lon is not None:
            return lat, lon, "granted"

    return None, None, None


async def get_location_from_coordinates(latitude: float, longitude: float) -> Dict[str, Optional[str]]:
    """
    Reverse geocode GPS coordinates using OpenStreetMap Nominatim.

    Returns:
        {
            "country": "United States",
            "city": "New York",
            "region": "New York",
            "timezone": "UTC",
            "isp": "Browser GPS",
            "full_address": "..."
        }
    """
    try:
        params = {
            "format": "json",
            "lat": latitude,
            "lon": longitude,
            "zoom": 12,
            "addressdetails": 1
        }
        headers = {
            "User-Agent": "zero-trust-fullstack/1.0"
        }
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                "https://nominatim.openstreetmap.org/reverse",
                params=params,
                headers=headers
            )

        if response.status_code == 200:
            data = response.json()
            address = data.get("address", {}) if isinstance(data, dict) else {}

            city = (
                address.get("city")
                or address.get("town")
                or address.get("village")
                or address.get("hamlet")
            )
            region = address.get("state") or address.get("region")
            country = address.get("country")

            return {
                "country": country or "Unknown",
                "city": city or "Unknown",
                "region": region or "Unknown",
                "timezone": "UTC",
                "isp": "Browser GPS",
                "full_address": data.get("display_name") if isinstance(data, dict) else None
            }
    except Exception as e:
        logger.error(f"Reverse geocoding error for coords {latitude}, {longitude}: {e}")

    return {
        "country": "Unknown",
        "city": "Unknown",
        "region": "Unknown",
        "timezone": "UTC",
        "isp": "Unknown",
        "full_address": None
    }


async def resolve_location_data(
    ip_address: str,
    request: Request,
    browser_location: Optional[dict]
) -> Tuple[Dict[str, Optional[str]], Optional[float], Optional[float]]:
    lat, lon, status = _extract_browser_coordinates(browser_location, request)
    if lat is not None and lon is not None and status == "granted":
        gps_data = await get_location_from_coordinates(lat, lon)
        if gps_data.get("country") != "Unknown" or gps_data.get("city") != "Unknown":
            return gps_data, lat, lon

    ip_data = await get_location_from_ip(ip_address)
    return ip_data, lat, lon

async def get_location_from_ip(ip_address: str) -> Dict[str, Optional[str]]:
    """
    Fetch geolocation data from IP address using ipapi.co (HTTPS, free tier)

    Returns:
        {
            "country": "United States",
            "city": "New York",
            "region": "New York",
            "timezone": "America/New_York",
            "isp": "AT&T Services"
        }

    Note:
    - For local/dev, IP will be private and return "Local"
    - For real-world accuracy, ensure your proxy forwards X-Forwarded-For
    """
    # Skip localhost/private IPs
    if ip_address in ["localhost", "unknown"]:
        return {
            "country": "Local",
            "city": "Local",
            "region": "Local",
            "timezone": "UTC",
            "isp": "Local Network"
        }

    try:
        ip_obj = ipaddress.ip_address(ip_address)
        if ip_obj.is_private or ip_obj.is_loopback:
            return {
                "country": "Local",
                "city": "Local",
                "region": "Local",
                "timezone": "UTC",
                "isp": "Local Network"
            }
    except ValueError:
        return {
            "country": "Local",
            "city": "Local",
            "region": "Local",
            "timezone": "UTC",
            "isp": "Local Network"
        }

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"https://ipapi.co/{ip_address}/json/")

            if response.status_code == 200:
                data = response.json()

                if not data.get("error"):
                    return {
                        "country": data.get("country_name", "Unknown"),
                        "city": data.get("city", "Unknown"),
                        "region": data.get("region", "Unknown"),
                        "timezone": data.get("timezone", "UTC"),
                        "isp": data.get("org", "Unknown")
                    }
    except Exception as e:
        logger.error(f"Geolocation API error for IP {ip_address}: {e}")

    # Fallback if API fails
    return {
        "country": "Unknown",
        "city": "Unknown",
        "region": "Unknown",
        "timezone": "UTC",
        "isp": "Unknown"
    }


def get_location_string(location_data: Dict[str, Optional[str]]) -> str:
    """Format location data as a readable string"""
    city = location_data.get("city", "Unknown")
    country = location_data.get("country", "Unknown")
    
    if city and country and city != "Unknown" and country != "Unknown":
        return f"{city}, {country}"
    elif country and country != "Unknown":
        return country
    else:
        return "Unknown Location"


# =============================================================================
# RISK SCORING
# =============================================================================

def calculate_login_risk_score(
    different_country: bool,
    multiple_failed_attempts: bool,
    new_device: bool,
    multiple_simultaneous_sessions: bool
) -> int:
    """
    PHASE 2 risk scoring (integer points):
    - Different country login: +4
    - Multiple failed attempts: +3
    - New device: +2
    - Multiple simultaneous sessions: +2
    """
    risk_score = 0

    if different_country:
        risk_score += 4
    if multiple_failed_attempts:
        risk_score += 3
    if new_device:
        risk_score += 2
    if multiple_simultaneous_sessions:
        risk_score += 2

    return risk_score


def get_risk_status(risk_score: int) -> str:
    """Auto-flag as suspicious when risk_score >= 5"""
    return "suspicious" if risk_score >= 5 else "normal"


def parse_login_ip_history(raw: str) -> list[str]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, list):
            return [str(ip) for ip in data]
    except Exception:
        return []
    return []


def update_login_ip_history(user, ip_address: str) -> str:
    """Append IP to history, keep last 10 entries, return JSON string."""
    history = parse_login_ip_history(user.login_ip_history)
    history.append(ip_address)
    history = history[-10:]
    return json.dumps(history)


# =============================================================================
# SESSION HELPERS
# =============================================================================

def generate_session_summary(session) -> str:
    """Generate human-readable session summary"""
    return f"{session.device} from {session.city or 'Unknown'}, {session.country or 'Unknown'} ({session.ip_address})"


# =============================================================================
# AGENT TRUST SCORE MANAGEMENT
# =============================================================================

def calculate_agent_trust_score(
    current_score: float,
    last_seen_at: Optional[object] = None,
    suspicious_flag: bool = False
) -> float:
    """
    Calculate updated device trust score based on agent activity.
    
    Rules:
    - If no heartbeat for >2 minutes: score -= 20 (stale device)
    - If suspicious flag in telemetry: score -= 30 (anomaly detected)
    - Minimum trust_score = 0
    - Maximum = 100
    
    Args:
        current_score: Current trust score (0-100)
        last_seen_at: Datetime of last heartbeat. If None or older than 2 min, apply penalty
        suspicious_flag: Whether telemetry indicates suspicious activity
        
    Returns:
        Updated trust score (0-100)
    """
    from datetime import timedelta
    
    updated_score = current_score
    now = now_ist()
    
    # Check if device is stale (>2 minutes without heartbeat)
    if last_seen_at:
        try:
            last_seen_at = ensure_ist(last_seen_at)
            time_since_last_seen = now - last_seen_at
            if time_since_last_seen > timedelta(minutes=2):
                updated_score -= 20
                logger.warning(f"Device stale for {time_since_last_seen}. Score penalty applied.")
        except Exception as e:
            logger.error(f"Error calculating stale device score: {e}")
    
    # Apply penalty for suspicious telemetry
    if suspicious_flag:
        updated_score -= 30
        logger.warning("Suspicious telemetry detected. Score penalty applied.")
    
    # Enforce bounds
    updated_score = max(0, min(100, updated_score))
    
    return updated_score


def verify_agent_token(token: str, agent_token_hash: str) -> bool:
    """
    Verify agent token matches stored hash.
    
    Args:
        token: JWT token from request
        agent_token_hash: Stored SHA256 hash of token
        
    Returns:
        True if tokens match, False otherwise
    """
    import hashlib
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    return token_hash == agent_token_hash


def hash_agent_token(token: str) -> str:
    """
    Create SHA256 hash of agent token for secure storage.
    
    PHASE B: Updated to work with secret tokens (not JWT).
    Secret tokens are random 64-byte values, hashed with SHA256.
    
    Args:
        token: Secret token to hash
        
    Returns:
        SHA256 hex digest
    """
    import hashlib
    return hashlib.sha256(token.encode()).hexdigest()


# =============================================================================
# PHASE B: SECURE SECRET TOKEN GENERATION
# =============================================================================

def generate_agent_token() -> str:
    """
    Generate cryptographically secure random token for agent authentication.
    
    PHASE B: Replace JWT with random secret token.
    
    Returns:
        128-character hex string (64 random bytes)
        
    Example:
        Token: "a7f3c9e2b1d4f6a8c0e1f2d3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1"
    """
    import secrets
    # Generate 64 random bytes, return as hex string (128 chars)
    return secrets.token_hex(64)


def validate_agent_token_rotation(
    agent_token_rotated_at: Optional[object],
    max_age_days: int = 90
) -> bool:
    """
    Check if agent token needs rotation based on age.
    
    PHASE B: Force token rotation every N days for security.
    
    Args:
        agent_token_rotated_at: Datetime of last rotation
        max_age_days: Maximum token age in days (default 90)
        
    Returns:
        True if token requires rotation, False if still valid
    """
    from datetime import timedelta
    
    if agent_token_rotated_at is None:
        # Never rotated - must rotate now
        return True
    
    try:
        rotated_at = ensure_ist(agent_token_rotated_at)
        if rotated_at is None:
            return True
        age = now_ist() - rotated_at
        return age > timedelta(days=max_age_days)
    except Exception as e:
        logger.error(f"Error checking token age: {e}")
        return False

# =============================================================================
# PHASE B: SESSION REVOCATION ON TRUST DROP
# =============================================================================

def revoke_device_sessions(db, device_id: int, reason: str = "Trust score threshold exceeded") -> int:
    """
    Revoke all active sessions for a device when trust score drops below threshold.
    
    PHASE B: Enforces immediate logout when device becomes untrusted.
    
    Args:
        db: Database session
        device_id: Device ID whose sessions to revoke
        reason: Reason for revocation (logged)
        
    Returns:
        Number of sessions revoked
    """
    from datetime import datetime
    
    try:
        # Find all active sessions for this device
        from models import Session
        
        # Update criteria: active sessions for the device
        sessions_to_revoke = db.query(Session).filter(
            Session.device_id == device_id,
            Session.is_active == True
        ).all()
        
        revoked_count = 0
        now = now_ist()
        
        for session in sessions_to_revoke:
            session.is_active = False
            session.logout_at = now
            revoked_count += 1
            logger.warning(
                f"Session revoked for device {device_id}: {reason} (session_id: {session.session_id[:16]}...)"
            )
        
        if revoked_count > 0:
            db.commit()
        
        return revoked_count
        
    except Exception as e:
        logger.error(f"Error revoking device sessions: {e}")
        db.rollback()
        return 0


# =============================================================================
# ENHANCED RISK SCORING & SUSPICIOUS LOGIN DETECTION
# =============================================================================

def calculate_comprehensive_risk_score(
    user_id: int,
    ip_address: str,
    country: str,
    city: Optional[str],
    browser: str,
    os: str,
    device: str,
    login_hour: int,
    db
) -> tuple[float, list[str]]:
    """
    Calculate sophisticated risk score for login attempt.
    
    Risk factors weighted 0.0-1.0:
    - New country: 0.4 (HIGH RISK)
    - New IP address: 0.2 (MEDIUM RISK)  
    - New device/browser: 0.2 (MEDIUM RISK)
    - Unusual login time: 0.1 (LOW RISK)
    - Rapid location change: 0.3 (HIGH RISK)
    - First-time login: 0.15 (MEDIUM-LOW RISK)
    
    Returns:
        (risk_score, risk_factors)
        - risk_score: 0.0 (safe) to 1.0 (critical)
        - risk_factors: list of detected issues
    """
    from models import Session as SessionModel, User
    from datetime import timedelta
    
    risk_score = 0.0
    risk_factors = []
    
    # Fetch user's historical data
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return 0.5, ["User not found"]
    
    # Get user's previous sessions
    previous_sessions = db.query(SessionModel).filter(
        SessionModel.user_id == user_id
    ).order_by(SessionModel.login_at.desc()).limit(20).all()
    
    # Factor 1: New Country (HIGH RISK)
    previous_countries = set([s.country for s in previous_sessions if s.country])
    if country and country not in ["LOCAL", "UNKNOWN", "Unknown"]:
        if previous_countries and country not in previous_countries:
            risk_score += 0.4
            risk_factors.append(f"New country: {country}")
    
    # Factor 2: New IP Address (MEDIUM RISK)
    previous_ips = set([s.ip_address for s in previous_sessions if s.ip_address])
    if ip_address not in previous_ips and ip_address not in ["127.0.0.1", "localhost"]:
        risk_score += 0.2
        risk_factors.append(f"New IP address")
    
    # Factor 3: New Device/Browser Combination (MEDIUM RISK)
    previous_browsers = set([f"{s.browser}|{s.os}" for s in previous_sessions if s.browser and s.os])
    current_device_sig = f"{browser}|{os}"
    if previous_browsers and current_device_sig not in previous_browsers:
        risk_score += 0.2
        risk_factors.append(f"New device/browser")
    
    # Factor 4: Unusual Login Time (LOW RISK)
    if previous_sessions:
        login_hours = [s.login_at.hour for s in previous_sessions if s.login_at]
        if login_hours:
            hour_frequency = login_hours.count(login_hour) / len(login_hours)
            # Flag if this hour appears < 10% of time and we have enough data
            if hour_frequency < 0.1 and len(login_hours) >= 5:
                risk_score += 0.1
                risk_factors.append(f"Unusual login time: {login_hour}:00")
    
    # Factor 5: Rapid location change (HIGH RISK)
    if previous_sessions:
        last_session = previous_sessions[0]
        last_login_at = ensure_ist(last_session.login_at)
        time_since_last = now_ist() - last_login_at
        
        if time_since_last < timedelta(hours=2):
            if last_session.country and country:
                if last_session.country != country and country not in ["LOCAL", "UNKNOWN"]:
                    risk_score += 0.3
                    risk_factors.append(f"Rapid location change: {last_session.country} → {country}")
    
    # Factor 6: First-time login (MEDIUM-LOW RISK)
    if not previous_sessions:
        risk_score += 0.15
        risk_factors.append("First login from this account")
    
    # Cap risk score at 1.0
    risk_score = min(risk_score, 1.0)
    
    return risk_score, risk_factors


def get_comprehensive_risk_status(risk_score: float) -> str:
    """
    Convert float risk score to status category.
    
    - 0.0 - 0.3: normal (green)
    - 0.3 - 0.6: suspicious (yellow)
    - 0.6 - 1.0: critical (red)
    """
    if risk_score < 0.3:
        return "normal"
    elif risk_score < 0.6:
        return "suspicious"
    else:
        return "critical"


# =============================================================================
# EMAIL ALERTS FOR SUSPICIOUS LOGINS
# =============================================================================

async def send_suspicious_login_email(
    user_email: str,
    user_name: str,
    ip_address: str,
    country: str,
    city: str,
    latitude: Optional[float],
    longitude: Optional[float],
    browser: str,
    os: str,
    timestamp,
    risk_score: float,
    risk_factors: list[str]
) -> bool:
    """
    Send email alert for suspicious login attempt.
    
    Email includes:
    - IP, Country, City, Timestamp
    - Risk score and factors
    - Google Maps link (if lat/lng available)
    - Browser and OS info
    
    Returns:
        True if email sent successfully, False otherwise
    """
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    import os
    
    # Get SMTP config from environment
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    from_email = os.getenv("ALERT_FROM_EMAIL", smtp_user)
    
    # Skip if SMTP not configured
    if not smtp_user or not smtp_password:
        logger.warning(f"⚠️ SMTP not configured - skipping email alert for {user_email}")
        return False
    
    # Build email content
    subject = f"⚠️ Suspicious Login Detected - {country}"
    
    # Create Google Maps link if coordinates available
    maps_link = ""
    if latitude and longitude:
        maps_link = f"https://www.google.com/maps?q={latitude},{longitude}"
    
    # Format risk factors as bullet list
    factors_html = "<ul>"
    for factor in risk_factors:
        factors_html += f"<li>{factor}</li>"
    factors_html += "</ul>"
    
    # Determine risk level color
    if risk_score >= 0.6:
        risk_color = "#dc3545"  # red
        risk_level = "CRITICAL"
    elif risk_score >= 0.3:
        risk_color = "#ffc107"  # yellow
        risk_level = "SUSPICIOUS"
    else:
        risk_color = "#28a745"  # green
        risk_level = "NORMAL"
    
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 0 auto; padding: 20px; }}
            .header {{ background: #f8f9fa; padding: 20px; border-radius: 5px; text-align: center; }}
            .alert {{ background: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; margin: 20px 0; }}
            .info-table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            .info-table th {{ background: #f8f9fa; padding: 10px; text-align: left; }}
            .info-table td {{ padding: 10px; border-bottom: 1px solid #dee2e6; }}
            .risk-badge {{ display: inline-block; padding: 5px 15px; border-radius: 20px; 
                          background: {risk_color}; color: white; font-weight: bold; }}
            .button {{ display: inline-block; padding: 12px 24px; background: #007bff; 
                      color: white; text-decoration: none; border-radius: 5px; margin: 10px 0; }}
            .footer {{ text-align: center; padding: 20px; font-size: 12px; color: #6c757d; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h2>🔒 Zero Trust Security Alert</h2>
                <p>Suspicious login activity detected on your account</p>
            </div>
            
            <div class="alert">
                <strong>Hello {user_name},</strong><br>
                We detected a login to your account that appears unusual based on your typical behavior.
            </div>
            
            <table class="info-table">
                <tr>
                    <th colspan="2">Login Details</th>
                </tr>
                <tr>
                    <td><strong>Time:</strong></td>
                    <td>{timestamp.strftime('%B %d, %Y at %I:%M %p UTC')}</td>
                </tr>
                <tr>
                    <td><strong>Location:</strong></td>
                    <td>{city}, {country}</td>
                </tr>
                <tr>
                    <td><strong>IP Address:</strong></td>
                    <td>{ip_address}</td>
                </tr>
                <tr>
                    <td><strong>Browser:</strong></td>
                    <td>{browser}</td>
                </tr>
                <tr>
                    <td><strong>Operating System:</strong></td>
                    <td>{os}</td>
                </tr>
                <tr>
                    <td><strong>Risk Level:</strong></td>
                    <td><span class="risk-badge">{risk_level}</span> ({risk_score:.2f}/1.0)</td>
                </tr>
            </table>
            
            <h3>Why was this flagged?</h3>
            {factors_html}
            
            {f'<p><a href="{maps_link}" class="button">📍 View Location on Google Maps</a></p>' if maps_link else ''}
            
            <div class="alert">
                <strong>What should you do?</strong><br>
                • If this was you, you can safely ignore this email<br>
                • If you don't recognize this activity, immediately change your password and contact your administrator<br>
                • Review your recent account activity for any suspicious behavior
            </div>
            
            <div class="footer">
                <p>This is an automated security alert from Zero Trust Authentication System</p>
                <p>Do not reply to this email</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    try:
        # Create message
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = from_email
        msg['To'] = user_email
        
        # Attach HTML body
        html_part = MIMEText(html_body, 'html')
        msg.attach(html_part)
        
        # Send email
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(msg)
        
        logger.info(f"✅ Suspicious login alert sent to {user_email}")
        return True
        
    except Exception as e:
        logger.error(f"❌ Failed to send email alert: {e}")
        return False


# =============================================================================
# SESSION CREATION HELPER
# =============================================================================

async def create_login_session(
    db,
    user_id: int,
    request: Request,
    device_id: Optional[int],
    browser_location: Optional[dict] = None,
    risk_threshold: float = 0.5
):
    """
    Create comprehensive login session with risk assessment and email alerts.
    
    Args:
        db: Database session
        user_id: User ID
        request: FastAPI request object
        device_id: Device ID (optional)
        browser_location: GPS coordinates from browser (optional)
        risk_threshold: Send email if risk_score >= threshold
        
    Returns:
        Session object
    """
    from models import Session as SessionModel, User
    from datetime import datetime
    
    # Extract client data
    ip_address = get_client_ip(request)
    user_agent_info = get_user_agent_info(request)
    
    location_data, latitude, longitude = await resolve_location_data(
        ip_address=ip_address,
        request=request,
        browser_location=browser_location
    )
    country = location_data.get("country", "Unknown")
    city = location_data.get("city", "Unknown")
    
    # Calculate risk score
    login_hour = now_ist().hour
    risk_score, risk_factors = calculate_comprehensive_risk_score(
        user_id=user_id,
        ip_address=ip_address,
        country=country,
        city=city,
        browser=user_agent_info.get("browser", "Unknown"),
        os=user_agent_info.get("os", "Unknown"),
        device=user_agent_info.get("device", "Unknown"),
        login_hour=login_hour,
        db=db
    )
    
    risk_status = get_comprehensive_risk_status(risk_score)
    
    # Create session
    session = SessionModel(
        user_id=user_id,
        device_id=device_id,
        ip_address=ip_address,
        country=country,
        city=city,
        latitude=latitude,
        longitude=longitude,
        browser=user_agent_info.get("browser"),
        os=user_agent_info.get("os"),
        device=user_agent_info.get("device"),
        user_agent=request.headers.get("User-Agent"),
        risk_score=risk_score,
        status=risk_status,
        risk_factors=json.dumps(risk_factors) if risk_factors else None,
        is_active=True
    )
    
    db.add(session)
    db.commit()
    db.refresh(session)
    
    # Send email alert if risk exceeds threshold
    if risk_score >= risk_threshold:
        user = db.query(User).filter(User.id == user_id).first()
        if user:
            user_email = user.company_email or user.personal_email
            if user_email:
                # Send email asynchronously (don't block login)
                try:
                    await send_suspicious_login_email(
                        user_email=user_email,
                        user_name=user.name,
                        ip_address=ip_address,
                        country=country,
                        city=city,
                        latitude=latitude,
                        longitude=longitude,
                        browser=user_agent_info.get("browser", "Unknown"),
                        os=user_agent_info.get("os", "Unknown"),
                        timestamp=session.login_at,
                        risk_score=risk_score,
                        risk_factors=risk_factors
                    )
                except Exception as e:
                    logger.error(f"Failed to send suspicious login email: {e}")
    
    # Update user's login history
    user = db.query(User).filter(User.id == user_id).first()
    if user:
        user.last_login_country = country
        user.login_ip_history = update_login_ip_history(user, ip_address)
        user.last_login_at = now_ist()
        db.commit()
    
    return session