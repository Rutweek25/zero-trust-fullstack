"""
Security utilities for Zero Trust authentication:
- IP geolocation
- User-agent parsing
- Risk scoring
- Suspicious login detection
- Email alerts
"""
import json
import httpx
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from time_utils import now_ist, ensure_ist
from typing import Dict, List, Optional, Tuple, Any
from user_agents import parse as parse_user_agent
from sqlalchemy.orm import Session
import os
from models import Session as SessionModel, User, Log


# ==================== IP GEOLOCATION ====================

async def get_ip_geolocation(ip_address: str) -> Dict[str, Any]:
    """
    Get geolocation data from IP address using ipapi.co
    
    Returns:
        {
            'ip': '8.8.8.8',
            'city': 'Mountain View',
            'region': 'California',
            'country': 'US',
            'country_name': 'United States',
            'latitude': 37.4056,
            'longitude': -122.0775,
            'timezone': 'America/Los_Angeles',
            'error': None
        }
    """
    # Skip localhost and private IPs
    if ip_address in ['127.0.0.1', 'localhost'] or ip_address.startswith('192.168.') or ip_address.startswith('10.'):
        return {
            'ip': ip_address,
            'city': 'Local',
            'region': 'Local',
            'country': 'LOCAL',
            'country_name': 'Local Network',
            'latitude': None,
            'longitude': None,
            'timezone': None,
            'error': 'Private IP address'
        }
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"https://ipapi.co/{ip_address}/json/")
            
            if response.status_code == 200:
                data = response.json()
                
                # ipapi.co returns 'error' field on failure
                if 'error' in data and data['error']:
                    return {
                        'ip': ip_address,
                        'city': 'Unknown',
                        'region': 'Unknown',
                        'country': 'UNKNOWN',
                        'country_name': 'Unknown',
                        'latitude': None,
                        'longitude': None,
                        'timezone': None,
                        'error': data.get('reason', 'Geolocation failed')
                    }
                
                return {
                    'ip': data.get('ip', ip_address),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'country': data.get('country_code', 'UNKNOWN'),
                    'country_name': data.get('country_name', 'Unknown'),
                    'latitude': data.get('latitude'),
                    'longitude': data.get('longitude'),
                    'timezone': data.get('timezone'),
                    'error': None
                }
            else:
                raise Exception(f"HTTP {response.status_code}")
                
    except Exception as e:
        return {
            'ip': ip_address,
            'city': 'Unknown',
            'region': 'Unknown',
            'country': 'UNKNOWN',
            'country_name': 'Unknown',
            'latitude': None,
            'longitude': None,
            'timezone': None,
            'error': str(e)
        }


def extract_client_ip(request) -> str:
    """
    Extract real client IP from request, handling proxies and load balancers.
    Critical for Netlify deployment (checks X-Forwarded-For header).
    
    Priority order:
    1. X-Forwarded-For (first IP in chain - original client)
    2. X-Real-IP
    3. request.client.host (direct connection)
    """
    # X-Forwarded-For contains comma-separated list: "client, proxy1, proxy2"
    # We want the FIRST IP (original client)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # Take first IP from comma-separated list
        client_ip = forwarded_for.split(",")[0].strip()
        return client_ip
    
    # Fallback to X-Real-IP
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # Last resort: direct connection IP
    if request.client and request.client.host:
        return request.client.host
    
    return "unknown"


# ==================== USER AGENT PARSING ====================

def parse_user_agent_string(user_agent_string: str) -> Dict[str, str]:
    """
    Parse user agent string to extract browser, OS, device info.
    
    Returns:
        {
            'browser': 'Chrome 120.0',
            'os': 'Windows 10',
            'device': 'PC',
            'is_mobile': False,
            'is_tablet': False,
            'is_bot': False
        }
    """
    if not user_agent_string:
        return {
            'browser': 'Unknown',
            'os': 'Unknown',
            'device': 'Unknown',
            'is_mobile': False,
            'is_tablet': False,
            'is_bot': False
        }
    
    try:
        ua = parse_user_agent(user_agent_string)
        
        # Browser info
        browser_family = ua.browser.family or "Unknown"
        browser_version = ua.browser.version_string or ""
        browser = f"{browser_family} {browser_version}".strip()
        
        # OS info
        os_family = ua.os.family or "Unknown"
        os_version = ua.os.version_string or ""
        os = f"{os_family} {os_version}".strip()
        
        # Device type
        if ua.is_mobile:
            device = "Mobile"
        elif ua.is_tablet:
            device = "Tablet"
        elif ua.is_pc:
            device = "PC"
        else:
            device = "Unknown"
        
        return {
            'browser': browser,
            'os': os,
            'device': device,
            'is_mobile': ua.is_mobile,
            'is_tablet': ua.is_tablet,
            'is_bot': ua.is_bot
        }
    except Exception as e:
        return {
            'browser': 'Unknown',
            'os': 'Unknown',
            'device': 'Unknown',
            'is_mobile': False,
            'is_tablet': False,
            'is_bot': False
        }


# ==================== RISK SCORING ====================

def calculate_login_risk_score(
    user_id: int,
    ip_address: str,
    country: str,
    city: Optional[str],
    browser: str,
    os: str,
    device: str,
    login_hour: int,
    db: Session
) -> Tuple[float, List[str]]:
    """
    Calculate risk score for a login attempt based on multiple factors.
    
    Returns:
        (risk_score, risk_factors)
        - risk_score: 0.0 (safe) to 1.0 (critical)
        - risk_factors: list of detected issues
    """
    risk_score = 0.0
    risk_factors = []
    
    # Fetch user's historical data
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return 0.5, ["User not found"]
    
    # Get user's previous sessions
    previous_sessions = db.query(SessionModel).filter(
        SessionModel.user_id == user_id,
        SessionModel.id != None  # Exclude current session if already created
    ).order_by(SessionModel.login_at.desc()).limit(20).all()
    
    # Factor 1: New Country (HIGH RISK)
    previous_countries = set([s.country for s in previous_sessions if s.country])
    if country and country != "LOCAL" and country != "UNKNOWN":
        if previous_countries and country not in previous_countries:
            risk_score += 0.4
            risk_factors.append(f"New country: {country}")
    
    # Factor 2: New IP Address (MEDIUM RISK)
    previous_ips = set([s.ip_address for s in previous_sessions if s.ip_address])
    if ip_address not in previous_ips:
        risk_score += 0.2
        risk_factors.append(f"New IP address")
    
    # Factor 3: New Device/Browser Combination (MEDIUM RISK)
    previous_browsers = set([f"{s.browser}|{s.os}" for s in previous_sessions if s.browser and s.os])
    current_device_sig = f"{browser}|{os}"
    if previous_browsers and current_device_sig not in previous_browsers:
        risk_score += 0.2
        risk_factors.append(f"New device/browser")
    
    # Factor 4: Unusual Login Time (LOW RISK)
    # Check if user typically logs in during this hour
    if previous_sessions:
        login_hours = [s.login_at.hour for s in previous_sessions if s.login_at]
        # If this hour is not in user's typical pattern (appears < 10% of time)
        hour_frequency = login_hours.count(login_hour) / len(login_hours) if login_hours else 0
        if hour_frequency < 0.1 and len(login_hours) >= 5:  # Only if we have enough data
            risk_score += 0.1
            risk_factors.append(f"Unusual login time: {login_hour}:00")
    
    # Factor 5: Rapid location change (HIGH RISK)
    # If last login was from different country < 2 hours ago
    if previous_sessions:
        last_session = previous_sessions[0]
        last_login_at = ensure_ist(last_session.login_at)
        time_since_last = now_ist() - last_login_at if last_login_at else timedelta.max
        if time_since_last < timedelta(hours=2):
            if last_session.country and country and last_session.country != country:
                risk_score += 0.3
                risk_factors.append(f"Rapid location change: {last_session.country} → {country}")
    
    # Factor 6: First-time login (MEDIUM-LOW RISK)
    if not previous_sessions:
        risk_score += 0.15
        risk_factors.append("First login from this account")
    
    # Cap risk score at 1.0
    risk_score = min(risk_score, 1.0)
    
    return risk_score, risk_factors


def get_risk_status(risk_score: float) -> str:
    """
    Convert risk score to status category.
            last_login_at = ensure_ist(last_session.login_at)
            time_since_last = now_ist() - last_login_at if last_login_at else timedelta.max
    if risk_score < 0.3:
        return "normal"
    elif risk_score < 0.6:
        return "suspicious"
    else:
        return "critical"


# ==================== EMAIL ALERTS ====================

async def send_suspicious_login_alert(
    user_email: str,
    user_name: str,
    ip_address: str,
    country: str,
    city: str,
    latitude: Optional[float],
    longitude: Optional[float],
    browser: str,
    os: str,
    timestamp: datetime,
    risk_score: float,
    risk_factors: List[str]
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
    # Get SMTP config from environment
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_password = os.getenv("SMTP_PASSWORD")
    from_email = os.getenv("ALERT_FROM_EMAIL", smtp_user)
    
    # Skip if SMTP not configured
    if not smtp_user or not smtp_password:
        print(f"⚠️ SMTP not configured - skipping email alert for {user_email}")
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
        
        print(f"✅ Suspicious login alert sent to {user_email}")
        return True
        
    except Exception as e:
        print(f"❌ Failed to send email alert: {e}")
        return False


# ==================== HELPER FUNCTIONS ====================

def update_user_login_history(user: User, country: str, ip_address: str) -> None:
    """
    Track user's login countries and IPs for suspicious detection.
    Updates user.last_login_country and user.login_ip_history.
    """
    # Update last login country
    user.last_login_country = country
    
    # Update IP history (keep last 10 IPs as JSON array)
    try:
        if user.login_ip_history:
            ip_history = json.loads(user.login_ip_history)
            if not isinstance(ip_history, list):
                ip_history = []
        else:
            ip_history = []
        
        # Add new IP if not already present
        if ip_address not in ip_history:
            ip_history.insert(0, ip_address)
            # Keep only last 10 IPs
            ip_history = ip_history[:10]
            user.login_ip_history = json.dumps(ip_history)
    except Exception:
        # Start fresh if parsing fails
        user.login_ip_history = json.dumps([ip_address])
