"""
Unit tests for Redis blacklist functionality.

These tests mock the Redis client to test blacklist logic without requiring
actual Redis connectivity, following the unit testing pattern established
for other external dependencies.
"""
import pytest
from unittest.mock import patch, AsyncMock

from app.auth.redis import get_redis, add_to_blacklist, is_blacklisted


class TestGetRedis:
    """Test Redis client connection management."""
    
    def _clear_redis_cache(self):
        """Helper to clear cached Redis connection."""
        if hasattr(get_redis, "redis"):
            delattr(get_redis, "redis")
    
    @pytest.mark.asyncio
    @patch('app.auth.redis.redis.from_url')
    async def test_get_redis_creates_connection(self, mock_from_url):
        """Test that get_redis creates a Redis connection."""
        mock_redis_client = AsyncMock()
        mock_from_url.return_value = mock_redis_client
        self._clear_redis_cache()
        
        result = await get_redis()
        
        assert result == mock_redis_client
        mock_from_url.assert_called_once_with("redis://localhost:6379/0")
    
    @pytest.mark.asyncio
    @patch('app.auth.redis.redis.from_url')
    async def test_get_redis_caches_connection(self, mock_from_url):
        """Test that get_redis reuses cached connection."""
        mock_redis_client = AsyncMock()
        mock_from_url.return_value = mock_redis_client
        self._clear_redis_cache()
        
        # Call twice
        result1 = await get_redis()
        result2 = await get_redis()
        
        assert result1 == result2
        # Should only create connection once
        mock_from_url.assert_called_once()
    
    @pytest.mark.asyncio
    @patch('app.auth.redis.settings.REDIS_URL', None)
    @patch('app.auth.redis.redis.from_url')
    async def test_get_redis_fallback_url(self, mock_from_url):
        """Test that get_redis uses fallback URL when REDIS_URL is None."""
        mock_redis_client = AsyncMock()
        mock_from_url.return_value = mock_redis_client
        self._clear_redis_cache()
        
        await get_redis()
        
        mock_from_url.assert_called_once_with("redis://localhost")


class TestAddToBlacklist:
    """Test JWT token blacklisting functionality."""
    
    @pytest.mark.asyncio
    @pytest.mark.parametrize("jti,exp,description", [
        ("test_jti_123", 3600, "1 hour"),
        ("another_jti_456", 7200, "2 hours"),
        ("zero_exp_jti", 0, "immediate expiration"),
    ])
    @patch('app.auth.redis.get_redis')
    async def test_add_to_blacklist(self, mock_get_redis, jti, exp, description):
        """Test adding JTI to blacklist with various expiry times."""
        mock_redis_client = AsyncMock()
        mock_get_redis.return_value = mock_redis_client
        
        await add_to_blacklist(jti, exp)
        
        mock_get_redis.assert_called_once()
        mock_redis_client.set.assert_called_once_with(
            f"blacklist:{jti}", 
            "1", 
            ex=exp
        )


class TestIsBlacklisted:
    """Test JWT token blacklist checking functionality."""
    
    @pytest.mark.asyncio
    @pytest.mark.parametrize("exists_return,expected_result", [
        (True, True),   # Blacklisted JTI
        (False, False), # Clean JTI
    ])
    @patch('app.auth.redis.get_redis')
    async def test_is_blacklisted(self, mock_get_redis, exists_return, expected_result):
        """Test checking JTI blacklist status."""
        mock_redis_client = AsyncMock()
        mock_redis_client.exists.return_value = exists_return
        mock_get_redis.return_value = mock_redis_client
        
        jti = f"test_jti_{expected_result}"
        result = await is_blacklisted(jti)
        
        assert result is expected_result
        mock_get_redis.assert_called_once()
        mock_redis_client.exists.assert_called_once_with(f"blacklist:{jti}")