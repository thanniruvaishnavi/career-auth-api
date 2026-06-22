package com.career.auth.service;

import com.career.auth.dto.*;
import com.career.auth.entity.User;
import com.career.auth.exception.EmailAlreadyExistsException;
import com.career.auth.exception.InvalidCredentialsException;
import com.career.auth.exception.InvalidTokenException;
import com.career.auth.repository.UserRepository;
import com.career.auth.security.JwtUtil;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    /** Pairs the JSON-safe AuthResponse with the raw refresh token, which the controller sets as an httpOnly cookie (never goes in the JSON body). */
    public record AuthResult(AuthResponse response, String refreshToken) {}

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final TokenService tokenService;

    private static final String TOKEN_TYPE = "Bearer";

    public AuthResult signup(SignupRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException("An account with this email already exists");
        }

        User user = User.builder()
                .fullName(request.getFullName())
                .email(request.getEmail().toLowerCase().trim())
                .password(passwordEncoder.encode(request.getPassword()))
                .role("USER")
                .build();

        userRepository.save(user);

        return generateAuthResult(user);
    }

    public AuthResult login(LoginRequest request) {
        String email = request.getEmail().toLowerCase().trim();

        if (tokenService.isLoginBlocked(email)) {
            throw new InvalidCredentialsException("Too many failed login attempts. Please try again in 15 minutes.");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new InvalidCredentialsException("Invalid email or password"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            tokenService.recordFailedLogin(email);
            throw new InvalidCredentialsException("Invalid email or password");
        }

        tokenService.clearFailedLogins(email);
        return generateAuthResult(user);
    }

    public AuthResult refresh(String refreshToken) {
        if (refreshToken == null || !jwtUtil.isTokenValid(refreshToken)) {
            throw new InvalidTokenException("Refresh token is invalid, expired, or missing");
        }

        Claims claims = jwtUtil.extractClaims(refreshToken);
        String tokenType = claims.get("tokenType", String.class);
        if (!"REFRESH".equals(tokenType)) {
            throw new InvalidTokenException("Provided token is not a refresh token");
        }

        String jti = claims.getId();
        String email = claims.getSubject();

        if (!tokenService.isRefreshTokenValid(jti, email)) {
            throw new InvalidTokenException("Refresh token has been revoked or expired. Please log in again.");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new InvalidTokenException("User no longer exists"));

        // Rotate refresh token: revoke old one, issue a new pair
        tokenService.revokeRefreshToken(jti);

        return generateAuthResult(user);
    }

    public void logout(String accessToken, String refreshToken) {
        if (accessToken != null && jwtUtil.isTokenValid(accessToken)) {
            String jti = jwtUtil.extractJti(accessToken);
            long remainingTtl = jwtUtil.extractClaims(accessToken).getExpiration().getTime() - System.currentTimeMillis();
            if (remainingTtl > 0) {
                tokenService.blocklistAccessToken(jti, remainingTtl);
            }
        }

        if (refreshToken != null && jwtUtil.isTokenValid(refreshToken)) {
            String jti = jwtUtil.extractJti(refreshToken);
            tokenService.revokeRefreshToken(jti);
        }
    }

    private AuthResult generateAuthResult(User user) {
        String accessToken = jwtUtil.generateAccessToken(user.getEmail(), user.getId(), user.getRole());
        String refreshToken = jwtUtil.generateRefreshToken(user.getEmail(), user.getId());

        String refreshJti = jwtUtil.extractJti(refreshToken);
        tokenService.storeRefreshToken(refreshJti, user.getEmail());

        UserDto userDto = UserDto.builder()
                .id(user.getId())
                .fullName(user.getFullName())
                .email(user.getEmail())
                .role(user.getRole())
                .build();

        AuthResponse response = AuthResponse.builder()
                .accessToken(accessToken)
                .tokenType(TOKEN_TYPE)
                .expiresIn(jwtUtil.getAccessTokenExpirationMs() / 1000)
                .user(userDto)
                .build();

        return new AuthResult(response, refreshToken);
    }
}
