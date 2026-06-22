package com.career.auth.controller;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Example of how to protect your future GitHub Optimizer / LinkedIn Optimizer
 * controllers. Any endpoint NOT listed as permitAll() in SecurityConfig
 * automatically requires a valid Bearer access token.
 */
@RestController
@RequestMapping("/api")
public class SampleProtectedController {

    @GetMapping("/profile/me")
    public Map<String, String> me(Authentication authentication) {
        // authentication.getName() returns the email set in JwtAuthFilter
        return Map.of(
                "email", authentication.getName(),
                "message", "This is a protected endpoint. You're authenticated!"
        );
    }
}
