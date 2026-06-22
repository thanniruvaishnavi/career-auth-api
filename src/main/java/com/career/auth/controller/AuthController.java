package com.career.auth.controller;

import com.career.auth.dto.*;
import com.career.auth.service.AuthService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    private static final String REFRESH_COOKIE_NAME = "refreshToken";
    private static final String REFRESH_COOKIE_PATH = "/api/auth";
    private static final Duration REFRESH_COOKIE_MAX_AGE = Duration.ofDays(7);

    @PostMapping("/signup")
    public ResponseEntity<AuthResponse> signup(@Valid @RequestBody SignupRequest request,
                                                HttpServletResponse response) {
        AuthService.AuthResult result = authService.signup(request);
        setRefreshCookie(response, result.refreshToken());
        return ResponseEntity.status(HttpStatus.CREATED).body(result.response());
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request,
                                               HttpServletResponse response) {
        AuthService.AuthResult result = authService.login(request);
        setRefreshCookie(response, result.refreshToken());
        return ResponseEntity.ok(result.response());
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@CookieValue(value = REFRESH_COOKIE_NAME, required = false) String refreshToken,
                                                 HttpServletResponse response) {
        AuthService.AuthResult result = authService.refresh(refreshToken);
        setRefreshCookie(response, result.refreshToken()); // rotated token -> new cookie
        return ResponseEntity.ok(result.response());
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(
            @RequestHeader(value = "Authorization", required = false) String authHeader,
            @CookieValue(value = REFRESH_COOKIE_NAME, required = false) String refreshToken,
            HttpServletResponse response) {

        String accessToken = (authHeader != null && authHeader.startsWith("Bearer "))
                ? authHeader.substring(7)
                : null;

        authService.logout(accessToken, refreshToken);
        clearRefreshCookie(response);

        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }

    private void setRefreshCookie(HttpServletResponse response, String refreshToken) {
        ResponseCookie cookie = ResponseCookie.from(REFRESH_COOKIE_NAME, refreshToken)
                .httpOnly(true)
                .secure(true)          // requires HTTPS — fine in prod (Render/Railway), use a proxy or allow non-secure only for local http testing
                .sameSite("None")      // required for cross-site (Lovable preview domain -> your API domain)
                .path(REFRESH_COOKIE_PATH)
                .maxAge(REFRESH_COOKIE_MAX_AGE)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    private void clearRefreshCookie(HttpServletResponse response) {
        ResponseCookie cookie = ResponseCookie.from(REFRESH_COOKIE_NAME, "")
                .httpOnly(true)
                .secure(true)
                .sameSite("None")
                .path(REFRESH_COOKIE_PATH)
                .maxAge(0)
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }
}
