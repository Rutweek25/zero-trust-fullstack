from datetime import timedelta
from time_utils import now_ist
from jose import JWTError, jwt
import bcrypt
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

# SECURITY KEYS - Load from .env
SECRET_KEY = os.getenv("SECRET_KEY", "your_super_secret_key_change_this_in_production_12345!@#$%")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 120))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))

# ---------------- HASH PASSWORD ----------------
def hash_password(password: str):
    # bcrypt has 72 byte input limit → truncate to avoid crash
    password_bytes = password[:72].encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')

# ---------------- VERIFY PASSWORD ----------------
def verify_password(plain_password: str, hashed_password: str):
    password_bytes = plain_password[:72].encode('utf-8')
    hashed_bytes = hashed_password.encode('utf-8')
    return bcrypt.checkpw(password_bytes, hashed_bytes)

# ---------------- ACCESS TOKEN (short-lived) ----------------
# Payload structure for device-bound sessions:
# {
#     "sub": user_id (used as user identifier),
#     "device_id": device.id (device from this session),
#     "session_id": session_id (unique session ID),
#     "exp": expiration timestamp
# }
def create_access_token(data: dict, expires_delta: timedelta = None):
    """
    Create a short-lived JWT access token.
    
    Expected data dict keys:
    - sub: user ID as STRING (required by JWT standard; cast to str(user.id))
    - device_id: device database ID (integer)
    - session_id: unique session UUID (string)
    
    Token expires in ACCESS_TOKEN_EXPIRE_MINUTES (default 120 minutes).
    
    NOTE: The "sub" claim MUST be a string per RFC 7519 and jose library validation.
    Always cast integer user IDs: data["sub"] = str(user.id)
    """
    to_encode = data.copy()
    expire = now_ist() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# ---------------- REFRESH TOKEN (long-lived) ----------------
def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = now_ist() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
