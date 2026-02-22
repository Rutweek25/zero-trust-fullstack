"""
Google OAuth utilities for Zero Trust system
Handles Google ID token validation and user creation/login
"""

from google.auth.transport import requests
from google.oauth2 import id_token
from dotenv import load_dotenv
import os
from pathlib import Path
from datetime import datetime, timezone
from time_utils import now_ist
from sqlalchemy.orm import Session
import models
from auth import hash_password
import uuid
import logging

# Load environment variables from .env file
env_path = Path(__file__).parent / '.env'
load_dotenv(dotenv_path=env_path)

GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
logger = logging.getLogger(__name__)


async def verify_google_token(token: str):
    """
    Verify Google ID token and extract user info
    Returns: dict with 'email', 'name', 'picture', 'sub' (Google User ID)
    
    Raises: ValueError with detailed error message if verification fails
    """
    if not GOOGLE_CLIENT_ID:
        error_msg = "GOOGLE_CLIENT_ID not configured in environment variables"
        logger.error(f"Google OAuth Error: {error_msg}")
        raise ValueError(error_msg)
    
    if not token or not token.strip():
        error_msg = "Google ID token is empty or missing"
        logger.error(f"Google OAuth Error: {error_msg}")
        raise ValueError(error_msg)
    
    try:
        logger.info(f"Attempting to verify Google token (length: {len(token)})")
        
        # Add clock skew tolerance of 10 seconds to handle timing differences
        idinfo = id_token.verify_oauth2_token(
            token, 
            requests.Request(), 
            GOOGLE_CLIENT_ID,
            clock_skew_in_seconds=10
        )
        
        logger.info(f"Token verified successfully for audience: {idinfo.get('aud')}")
        
        # Verify token is for the expected client
        if idinfo.get("aud") != GOOGLE_CLIENT_ID:
            error_msg = f"Token audience mismatch. Expected: {GOOGLE_CLIENT_ID}, Got: {idinfo.get('aud')}"
            logger.error(f"Google OAuth Error: {error_msg}")
            raise ValueError(error_msg)
        
        # Validate required fields
        email = idinfo.get("email")
        if not email:
            error_msg = "Google token missing 'email' field"
            logger.error(f"Google OAuth Error: {error_msg}")
            raise ValueError(error_msg)
        
        sub = idinfo.get("sub")
        if not sub:
            error_msg = "Google token missing 'sub' (user ID) field"
            logger.error(f"Google OAuth Error: {error_msg}")
            raise ValueError(error_msg)
        
        user_info = {
            "email": email,
            "name": idinfo.get("name", email.split("@")[0]),
            "picture": idinfo.get("picture"),
            "sub": sub,  # Google User ID
            "email_verified": idinfo.get("email_verified", False)
        }
        
        logger.info(f"Token successfully decoded for user: {email}")
        return user_info
    
    except ValueError:
        # Re-raise our custom ValueError messages
        raise
    except Exception as e:
        error_msg = f"Token verification failed: {str(e)}"
        logger.error(f"Google OAuth Error: {error_msg}")
        raise ValueError(error_msg)


def get_or_create_google_user(user_info: dict, db: Session):
    """
    Find user by Google email or create new user.
    Auto-generates username if needed.
    
    Args:
        user_info: dict with 'email', 'sub', 'name' (from Google token)
        db: SQLAlchemy session
    
    Returns: user object or raises ValueError if user_info invalid
    """
    # Validate user_info has required fields
    email = user_info.get("email")
    if not email or not isinstance(email, str) or "@" not in email:
        error_msg = f"Google user info has invalid email: {email}"
        logger.error(f"Google User Creation Error: {error_msg}")
        raise ValueError(f"Invalid email: {email}")
    
    sub = user_info.get("sub")
    if not sub or not isinstance(sub, str):
        error_msg = f"Google user info missing or invalid user ID (sub): {sub}"
        logger.error(f"Google User Creation Error: {error_msg}")
        raise ValueError("Missing Google user ID (sub)")
    
    logger.info(f"Processing Google user: {email} (sub: {sub[:10]}...)")
    
    # Try to find user by personal email (assuming Google email = personal email)
    user = db.query(models.User).filter(
        models.User.personal_email == email
    ).first()
    
    if user:
        logger.info(f"Existing user found: {user.username} (ID: {user.id})")
        return user
    
    # Create new user
    try:
        # Generate unique username from email prefix
        email_prefix = email.split("@")[0]
        base_username = email_prefix
        username = base_username
        counter = 1
        
        # Ensure username is unique
        while db.query(models.User).filter(
            models.User.username == username
        ).first():
            username = f"{base_username}{counter}"
            counter += 1
        
        logger.info(f"Creating new user: {username} with email: {email}")
        
        # Random dummy password (OAuth users don't use password login)
        dummy_password = f"oauth_{sub}_{uuid.uuid4().hex[:8]}"
        
        new_user = models.User(
            username=username,
            name=user_info.get("name", email_prefix),
            company_email=email,  # Use Google email as company email
            personal_email=email,
            password_hash=hash_password(dummy_password),
            auth_provider="google",
            role="user",
            status="active",
            created_at=now_ist()
        )
        
        db.add(new_user)
        db.flush()  # Flush to generate ID without commit
        
        logger.info(f"New user created: {username} (ID: {new_user.id}, email: {email})")
        return new_user
        
    except Exception as e:
        error_msg = f"Failed to create Google user: {str(e)}"
        logger.error(f"Google User Creation Error: {error_msg}")
        raise ValueError(error_msg)
