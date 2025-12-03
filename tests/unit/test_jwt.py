"""
Unit tests for JWT authentication functions.

These tests focus on core JWT utility functions that can be tested in isolation
without requiring database connections or external services.
"""
import pytest
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock
from jose import jwt
from fastapi import HTTPException

from app.auth.jwt import (
    verify_password,
    get_password_hash,
    create_token,
    decode_token,
    settings
)
from app.schemas.token import TokenType


class TestPasswordFunctions:
    """Test password hashing and verification functions."""
    
    def test_get_password_hash_creates_hash(self):
        """Test that get_password_hash creates a bcrypt hash."""
        password = "test_password_123"
        hashed = get_password_hash(password)
        
        # Bcrypt hashes start with $2b$ and are 60 characters long
        assert isinstance(hashed, str)
        assert hashed.startswith("$2b$")
        assert len(hashed) == 60
        
    def test_get_password_hash_different_passwords_different_hashes(self):
        """Test that different passwords produce different hashes."""
        password1 = "password1"
        password2 = "password2"
        
        hash1 = get_password_hash(password1)
        hash2 = get_password_hash(password2)
        
        assert hash1 != hash2
        
    def test_get_password_hash_same_password_different_hashes(self):
        """Test that same password produces different hashes (due to salt)."""
        password = "same_password"
        
        hash1 = get_password_hash(password)
        hash2 = get_password_hash(password)
        
        # Due to bcrypt salting, same password should produce different hashes
        assert hash1 != hash2
        
    @pytest.mark.parametrize("test_password,expected", [
        ("correct_password", True),   # Correct password should verify
        ("wrong_password", False),    # Wrong password should fail
        ("", False),                  # Empty password should fail
    ])
    def test_verify_password_scenarios(self, test_password, expected):
        """Test verify_password with various scenarios."""
        original_password = "correct_password"
        hashed = get_password_hash(original_password)
        
        result = verify_password(test_password, hashed)
        assert result is expected


class TestCreateToken:
    """Test JWT token creation function."""
    
    @pytest.mark.parametrize("user_id_type", ["string", "uuid"])
    def test_create_access_token_user_id_types(self, user_id_type):
        """Test creating access token with string and UUID user IDs."""
        token_type = TokenType.ACCESS
        
        if user_id_type == "string":
            user_id = "123e4567-e89b-12d3-a456-426614174000"
            expected_sub_val = user_id
        else:
            user_id = uuid.uuid4()
            expected_sub_val = str(user_id)
        
        token = create_token(user_id, token_type)
        
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Decode to verify contents
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert payload["sub"] == expected_sub_val
        assert payload["type"] == token_type.value
        assert "exp" in payload
        assert "iat" in payload
        assert "jti" in payload
        
    def test_create_refresh_token(self):
        """Test creating refresh token."""
        user_id = str(uuid.uuid4())
        token_type = TokenType.REFRESH
        
        token = create_token(user_id, token_type)
        
        payload = jwt.decode(token, settings.JWT_REFRESH_SECRET_KEY, algorithms=[settings.ALGORITHM])
        assert payload["sub"] == user_id
        assert payload["type"] == token_type.value
        
    def test_create_token_with_custom_expiry(self):
        """Test creating token with custom expiry time."""
        user_id = str(uuid.uuid4())
        token_type = TokenType.ACCESS
        custom_delta = timedelta(hours=2)
        
        token = create_token(user_id, token_type, expires_delta=custom_delta)
        
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
        
        # Check that expiry is approximately 2 hours from now
        exp_time = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        expected_exp = datetime.now(timezone.utc) + custom_delta
        
        # Allow 10 second tolerance
        assert abs((exp_time - expected_exp).total_seconds()) < 10
        
    @pytest.mark.parametrize("token_type,secret,time_unit,time_value", [
        (TokenType.ACCESS, "JWT_SECRET_KEY", "minutes", "ACCESS_TOKEN_EXPIRE_MINUTES"),
        (TokenType.REFRESH, "JWT_REFRESH_SECRET_KEY", "days", "REFRESH_TOKEN_EXPIRE_DAYS"),
    ])
    def test_create_token_default_expiry(self, token_type, secret, time_unit, time_value):
        """Test that tokens use correct default expiry times."""
        user_id = str(uuid.uuid4())
        
        token = create_token(user_id, token_type)
        
        secret_key = getattr(settings, secret)
        payload = jwt.decode(token, secret_key, algorithms=[settings.ALGORITHM])
        
        # Check that expiry matches settings
        exp_time = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        
        time_val = getattr(settings, time_value)
        if time_unit == "minutes":
            expected_exp = datetime.now(timezone.utc) + timedelta(minutes=time_val)
        else:  # days
            expected_exp = datetime.now(timezone.utc) + timedelta(days=time_val)
        
        # Allow 10 second tolerance
        assert abs((exp_time - expected_exp).total_seconds()) < 10
        
    def test_create_token_includes_jti(self):
        """Test that token includes unique JTI (JWT ID)."""
        user_id = str(uuid.uuid4())
        token_type = TokenType.ACCESS
        
        token1 = create_token(user_id, token_type)
        token2 = create_token(user_id, token_type)
        
        payload1 = jwt.decode(token1, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
        payload2 = jwt.decode(token2, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
        
        # JTI should be different for each token
        assert payload1["jti"] != payload2["jti"]
        assert len(payload1["jti"]) == 32  # secrets.token_hex(16) produces 32 chars
        
    @patch('app.auth.jwt.jwt.encode')
    def test_create_token_handles_encoding_error(self, mock_encode):
        """Test that create_token handles JWT encoding errors."""
        mock_encode.side_effect = Exception("Encoding failed")
        
        user_id = str(uuid.uuid4())
        token_type = TokenType.ACCESS
        
        with pytest.raises(HTTPException) as exc_info:
            create_token(user_id, token_type)
            
        assert exc_info.value.status_code == 500
        assert "Could not create token" in str(exc_info.value.detail)


class TestDecodeToken:
    """Test JWT token decoding function."""
    
    @pytest.mark.asyncio
    @pytest.mark.parametrize("token_type", [TokenType.ACCESS, TokenType.REFRESH])
    async def test_decode_valid_token(self, token_type):
        """Test decoding valid access and refresh tokens."""
        user_id = str(uuid.uuid4())
        
        # Create token
        token = create_token(user_id, token_type)
        
        # Mock Redis blacklist check
        with patch('app.auth.jwt.is_blacklisted', return_value=False):
            payload = await decode_token(token, token_type)
            
        assert payload["sub"] == user_id
        assert payload["type"] == token_type.value
        assert "exp" in payload
        assert "iat" in payload
        assert "jti" in payload
        
    @pytest.mark.asyncio
    async def test_decode_token_wrong_type(self):
        """Test that decoding fails when token type doesn't match."""
        user_id = str(uuid.uuid4())
        
        # Create a token manually with ACCESS type but decode with REFRESH secret  
        payload = {
            "sub": user_id,
            "type": TokenType.ACCESS.value,  # Access type in payload
            "exp": datetime.now(timezone.utc) + timedelta(minutes=30),
            "iat": datetime.now(timezone.utc),
            "jti": "test_jti"
        }
        
        # Create token with REFRESH secret so it can be decoded, but has wrong type
        token = jwt.encode(payload, settings.JWT_REFRESH_SECRET_KEY, algorithm=settings.ALGORITHM)
        
        with patch('app.auth.jwt.is_blacklisted', return_value=False):
            with pytest.raises(HTTPException) as exc_info:
                await decode_token(token, TokenType.REFRESH)
                
        assert exc_info.value.status_code == 401
        assert "Invalid token type" in str(exc_info.value.detail)
        
    @pytest.mark.asyncio
    async def test_decode_blacklisted_token(self):
        """Test that decoding fails for blacklisted tokens."""
        user_id = str(uuid.uuid4())
        token_type = TokenType.ACCESS
        
        token = create_token(user_id, token_type)
        
        # Mock token as blacklisted
        with patch('app.auth.jwt.is_blacklisted', return_value=True):
            with pytest.raises(HTTPException) as exc_info:
                await decode_token(token, token_type)
                
        assert exc_info.value.status_code == 401
        assert "Token has been revoked" in str(exc_info.value.detail)
        
    @pytest.mark.asyncio
    async def test_decode_expired_token(self):
        """Test that decoding fails for expired tokens."""
        user_id = str(uuid.uuid4())
        token_type = TokenType.ACCESS
        
        # Create token that expires immediately
        expired_delta = timedelta(seconds=-1)
        token = create_token(user_id, token_type, expires_delta=expired_delta)
        
        with patch('app.auth.jwt.is_blacklisted', return_value=False):
            with pytest.raises(HTTPException) as exc_info:
                await decode_token(token, token_type)
                
        assert exc_info.value.status_code == 401
        assert "Token has expired" in str(exc_info.value.detail)
        
    @pytest.mark.asyncio
    async def test_decode_token_skip_expiry_check(self):
        """Test decoding expired token with expiry check disabled."""
        user_id = str(uuid.uuid4())
        token_type = TokenType.ACCESS
        
        # Create expired token
        expired_delta = timedelta(seconds=-1)
        token = create_token(user_id, token_type, expires_delta=expired_delta)
        
        with patch('app.auth.jwt.is_blacklisted', return_value=False):
            payload = await decode_token(token, token_type, verify_exp=False)
            
        assert payload["sub"] == user_id
        assert payload["type"] == token_type.value
        
    @pytest.mark.asyncio
    async def test_decode_invalid_token(self):
        """Test that decoding fails for invalid/malformed tokens."""
        invalid_token = "invalid.jwt.token"
        
        with patch('app.auth.jwt.is_blacklisted', return_value=False):
            with pytest.raises(HTTPException) as exc_info:
                await decode_token(invalid_token, TokenType.ACCESS)
                
        assert exc_info.value.status_code == 401
        assert "Could not validate credentials" in str(exc_info.value.detail)
        
