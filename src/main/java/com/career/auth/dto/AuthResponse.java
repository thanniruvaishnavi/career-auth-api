package com.career.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {
    private String accessToken;
    private String tokenType;
    private long expiresIn; // seconds
    private UserDto user;
    // Note: refreshToken is intentionally NOT included here.
    // It is sent as an httpOnly cookie instead (see AuthController).
}
