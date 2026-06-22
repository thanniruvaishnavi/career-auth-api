package com.career.auth.service;

import com.career.auth.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * Stores refresh tokens in Redis keyed by their JWT ID (jti), mapped to the user's email.
 * This lets us:
 *  - Validate a refresh token is still "live" (not logged out / not revoked)
 *  - Instantly revoke a single session (logout) or all sessions (e.g. password change)
 *  - Avoid hitting the DB on every refresh call
 */
@Service
@RequiredArgsConstructor
public class TokenService {

    private final StringRedisTemplate redisTemplate;
    private final JwtUtil jwtUtil;

    private static final String REFRESH_PREFIX = "refresh_token:";
    private static final String BLOCKLIST_PREFIX = "blocklist:";

    /** Store a refresh token's jti -> email mapping with TTL matching the token expiry. */
    public void storeRefreshToken(String jti, String email) {
        String key = REFRESH_PREFIX + jti;
        redisTemplate.opsForValue().set(
                key,
                email,
                Duration.ofMillis(jwtUtil.getRefreshTokenExpirationMs())
        );
    }

    /** Check whether a given refresh token jti is still valid (present, not revoked). */
    public boolean isRefreshTokenValid(String jti, String email) {
        String key = REFRESH_PREFIX + jti;
        String storedEmail = redisTemplate.opsForValue().get(key);
        return storedEmail != null && storedEmail.equals(email);
    }

    /** Revoke a single refresh token (used on logout). */
    public void revokeRefreshToken(String jti) {
        redisTemplate.delete(REFRESH_PREFIX + jti);
    }

    /** Blocklist an access token's jti until its natural expiry (used on logout, for defense-in-depth). */
    public void blocklistAccessToken(String jti, long ttlMillis) {
        redisTemplate.opsForValue().set(
                BLOCKLIST_PREFIX + jti,
                "revoked",
                Duration.ofMillis(ttlMillis)
        );
    }

    public boolean isAccessTokenBlocklisted(String jti) {
        return redisTemplate.hasKey(BLOCKLIST_PREFIX + jti);
    }

    // --- Simple login rate limiting (optional bonus, mentioned in interviews) ---

    private static final String LOGIN_ATTEMPT_PREFIX = "login_attempts:";
    private static final int MAX_ATTEMPTS = 5;
    private static final Duration LOCK_WINDOW = Duration.ofMinutes(15);

    public boolean isLoginBlocked(String email) {
        String attempts = redisTemplate.opsForValue().get(LOGIN_ATTEMPT_PREFIX + email);
        return attempts != null && Integer.parseInt(attempts) >= MAX_ATTEMPTS;
    }

    public void recordFailedLogin(String email) {
        String key = LOGIN_ATTEMPT_PREFIX + email;
        Long count = redisTemplate.opsForValue().increment(key);
        if (count != null && count == 1L) {
            redisTemplate.expire(key, LOCK_WINDOW);
        }
    }

    public void clearFailedLogins(String email) {
        redisTemplate.delete(LOGIN_ATTEMPT_PREFIX + email);
    }
}
