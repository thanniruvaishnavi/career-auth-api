package com.career.auth.security;

import com.career.auth.service.TokenService;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final TokenService tokenService;

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                     @NonNull HttpServletResponse response,
                                     @NonNull FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);

        try {
            if (!jwtUtil.isTokenValid(token)) {
                filterChain.doFilter(request, response);
                return;
            }

            String tokenType = jwtUtil.extractTokenType(token);
            if (!"ACCESS".equals(tokenType)) {
                // Refresh tokens must never be used to authenticate normal requests
                filterChain.doFilter(request, response);
                return;
            }

            String jti = jwtUtil.extractJti(token);
            if (tokenService.isAccessTokenBlocklisted(jti)) {
                filterChain.doFilter(request, response);
                return;
            }

            String email = jwtUtil.extractEmail(token);
            String role = jwtUtil.extractClaims(token).get("role", String.class);

            if (SecurityContextHolder.getContext().getAuthentication() == null) {
                var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + (role == null ? "USER" : role)));
                var authToken = new UsernamePasswordAuthenticationToken(email, null, authorities);
                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

        } catch (JwtException ex) {
            // Invalid/expired token -> leave unauthenticated, let Spring Security reject downstream
        }

        filterChain.doFilter(request, response);
    }
}
