package com.career.auth.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.UUID;

@Component
public class JwtUtil {

    @Value("${app.jwt.secret}")
    private String secret;

    @Value("${app.jwt.access-token-expiration-ms}")
    private long accessTokenExpirationMs;

    @Value("${app.jwt.refresh-token-expiration-ms}")
    private long refreshTokenExpirationMs;

    private Key signingKey;

    @PostConstruct
    public void init() {
        // secret must be a Base64-encoded string of at least 256 bits for HS256
        this.signingKey = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public String generateAccessToken(String email, Long userId, String role) {
        return buildToken(email, userId, role, accessTokenExpirationMs, "ACCESS");
    }

    public String generateRefreshToken(String email, Long userId) {
        return buildToken(email, userId, null, refreshTokenExpirationMs, "REFRESH");
    }

    private String buildToken(String email, Long userId, String role, long expirationMs, String tokenType) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMs);

        JwtBuilder builder = Jwts.builder()
                .id(UUID.randomUUID().toString())
                .subject(email)
                .claim("userId", userId)
                .claim("tokenType", tokenType)
                .issuedAt(now)
                .expiration(expiry)
                .signWith(signingKey);

        if (role != null) {
            builder.claim("role", role);
        }
        return builder.compact();
    }

    public Claims extractClaims(String token) {
        return Jwts.parser()
                .verifyWith((javax.crypto.SecretKey) signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractEmail(String token) {
        return extractClaims(token).getSubject();
    }

    public Long extractUserId(String token) {
        return extractClaims(token).get("userId", Long.class);
    }

    public String extractJti(String token) {
        return extractClaims(token).getId();
    }

    public String extractTokenType(String token) {
        return extractClaims(token).get("tokenType", String.class);
    }

    public boolean isTokenValid(String token) {
        try {
            extractClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public long getRefreshTokenExpirationMs() {
        return refreshTokenExpirationMs;
    }

    public long getAccessTokenExpirationMs() {
        return accessTokenExpirationMs;
    }
}
