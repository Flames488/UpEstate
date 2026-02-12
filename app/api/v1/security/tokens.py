import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Tuple


class TokenManager:
    """Manager for generating and handling refresh tokens."""
    
    # Default token expiration period in days
    DEFAULT_TOKEN_EXPIRY_DAYS = 14
    
    @staticmethod
    def generate_refresh_token() -> Tuple[str, str]:
        """
        Generate a secure refresh token.
        
        Returns:
            Tuple containing (raw_token, hashed_token)
        
        Security Notes:
            - Uses secrets.token_urlsafe() for cryptographically secure random generation
            - Raw token is 64 bytes (512 bits) providing 256 bits of entropy
            - Token is hashed using SHA-256 before storage (never store raw tokens)
        """
        # Generate cryptographically secure random token
        raw_token = secrets.token_urlsafe(64)
        
        # Hash the token for secure storage (never store raw tokens in DB)
        hashed_token = hashlib.sha256(raw_token.encode()).hexdigest()
        
        return raw_token, hashed_token
    
    @staticmethod
    def calculate_expiry_time(days: int = DEFAULT_TOKEN_EXPIRY_DAYS) -> datetime:
        """
        Calculate the expiry datetime for a token.
        
        Args:
            days: Number of days until token expiry (default: 14)
            
        Returns:
            UTC datetime when the token expires
            
        Note:
            Uses UTC timezone for consistency across systems
        """
        return datetime.utcnow() + timedelta(days=days)
    
    @staticmethod
    def verify_token(raw_token: str, stored_hash: str) -> bool:
        """
        Verify if a raw token matches its stored hash.
        
        Args:
            raw_token: The raw token string to verify
            stored_hash: The previously stored hash to compare against
            
        Returns:
            True if token matches hash, False otherwise
        """
        calculated_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        return secrets.compare_digest(calculated_hash, stored_hash)


# Example usage
if __name__ == "__main__":
    # Generate a token pair
    raw_token, hashed_token = TokenManager.generate_refresh_token()
    print(f"Raw token (share with user): {raw_token[:50]}...")
    print(f"Hashed token (store in DB): {hashed_token[:50]}...")
    
    # Calculate expiry
    expiry_time = TokenManager.calculate_expiry_time()
    print(f"Token expires at (UTC): {expiry_time}")
    
    # Verify token
    is_valid = TokenManager.verify_token(raw_token, hashed_token)
    print(f"Token verification: {'✓ Valid' if is_valid else '✗ Invalid'}")