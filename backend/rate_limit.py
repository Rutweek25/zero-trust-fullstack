"""
PHASE B: Rate Limiting Middleware

Sliding window rate limiting for:
- IP-based limits (10 req/min per IP)
- Token-based limits (50 heartbeats/min per token)
- Endpoint-specific limits

Thread-safe using in-memory dictionary with cleanup.
"""

from typing import Dict, Tuple, Optional
from datetime import timedelta
from time_utils import now_ist
import hashlib
import logging

logger = logging.getLogger(__name__)


class RateLimiter:
    """
    Sliding window rate limiter for API endpoints.
    
    Stores timestamps of recent requests and checks if thresholds exceeded.
    Automatically cleans up old entries.
    """
    
    def __init__(self):
        # Dictionary: key -> list of request timestamps (int seconds since epoch)
        self._windows: Dict[str, list] = {}
        
        # Configuration
        self.IP_LIMIT_PER_MINUTE = 10      # 10 requests per minute per IP
        self.TOKEN_LIMIT_PER_MINUTE = 50   # 50 heartbeats per minute per token
        self.WINDOW_SIZE_SECONDS = 60      # Sliding window = 1 minute
        
    def _get_window_key(self, key_type: str, key_value: str) -> str:
        """Create stable key for rate limit window"""
        return f"{key_type}:{key_value}"
    
    def _cleanup_old_entries(self, now_ts: int, window: list) -> list:
        """Remove timestamps older than window size"""
        cutoff = now_ts - self.WINDOW_SIZE_SECONDS
        return [ts for ts in window if ts > cutoff]
    
    def check_ip_limit(self, ip_address: str) -> Tuple[bool, Optional[str]]:
        """
        Check if IP has exceeded rate limit.
        
        Args:
            ip_address: Client IP address
            
        Returns:
            Tuple of (allowed: bool, error_message: str | None)
        """
        key = self._get_window_key("ip", ip_address)
        now_ts = int(now_ist().timestamp())
        
        # Get current window, clean old entries
        window = self._windows.get(key, [])
        window = self._cleanup_old_entries(now_ts, window)
        
        # Check limit
        if len(window) >= self.IP_LIMIT_PER_MINUTE:
            remaining_wait = window[0] + self.WINDOW_SIZE_SECONDS - now_ts + 1
            error_msg = f"Rate limit exceeded. Retry after {remaining_wait} seconds"
            logger.warning(f"IP rate limit exceeded: {ip_address}")
            return False, error_msg
        
        # Add current request
        window.append(now_ts)
        self._windows[key] = window
        
        return True, None
    
    def check_token_limit(self, token_hash: str) -> Tuple[bool, Optional[str]]:
        """
        Check if token has exceeded rate limit on heartbeats.
        
        Args:
            token_hash: SHA256 hash of agent token
            
        Returns:
            Tuple of (allowed: bool, error_message: str | None)
        """
        key = self._get_window_key("token", token_hash)
        now_ts = int(now_ist().timestamp())
        
        # Get current window, clean old entries
        window = self._windows.get(key, [])
        window = self._cleanup_old_entries(now_ts, window)
        
        # Check limit
        if len(window) >= self.TOKEN_LIMIT_PER_MINUTE:
            remaining_wait = window[0] + self.WINDOW_SIZE_SECONDS - now_ts + 1
            error_msg = f"Heartbeat rate limit exceeded. Retry after {remaining_wait} seconds"
            logger.warning(f"Token rate limit exceeded: {token_hash[:16]}...")
            return False, error_msg
        
        # Add current request
        window.append(now_ts)
        self._windows[key] = window
        
        return True, None
    
    def get_status(self) -> Dict:
        """Get current limiter status (for monitoring)"""
        now_ts = int(now_ist().timestamp())
        
        # Clean all windows
        cleaned_keys = []
        for key in list(self._windows.keys()):
            self._windows[key] = self._cleanup_old_entries(now_ts, self._windows[key])
            if not self._windows[key]:
                del self._windows[key]
                cleaned_keys.append(key)
        
        return {
            "active_windows": len(self._windows),
            "cleaned_entries": len(cleaned_keys),
            "ip_limit": self.IP_LIMIT_PER_MINUTE,
            "token_limit": self.TOKEN_LIMIT_PER_MINUTE,
            "window_size": self.WINDOW_SIZE_SECONDS
        }


# Global rate limiter instance
_rate_limiter = RateLimiter()


# =============================================================================
# PUBLIC API
# =============================================================================

def check_rate_limit_ip(ip_address: str) -> Tuple[bool, Optional[str]]:
    """Check IP-based rate limit"""
    return _rate_limiter.check_ip_limit(ip_address)


def check_rate_limit_token(agent_token_hash: str) -> Tuple[bool, Optional[str]]:
    """Check token-based rate limit"""
    return _rate_limiter.check_token_limit(agent_token_hash)


def get_rate_limiter_status() -> Dict:
    """Get rate limiter status"""
    return _rate_limiter.get_status()
