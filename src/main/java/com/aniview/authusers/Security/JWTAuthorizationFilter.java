package com.aniview.authusers.Security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;

public class JWTAuthorizationFilter extends OncePerRequestFilter {

    private static final String SECRET_KEY = "mySecretKey123456789012345678901234567890";
    private static final String COOKIE_NAME = "AUTH_TOKEN";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        try {
            if (checkJWTToken(request)) {
                Claims claims = validateToken(request);
                if (claims.get("authorities") != null) {
                    setUpSpringAuthentication(claims);
                } else {
                    SecurityContextHolder.clearContext();
                }
            } else {
                SecurityContextHolder.clearContext();
            }
            chain.doFilter(request, response);
        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.sendError(HttpServletResponse.SC_FORBIDDEN, e.getMessage());
        }
    }

    private boolean checkJWTToken(HttpServletRequest request) {
        // Verificar si hay cookies y si contienen el AUTH_TOKEN
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (COOKIE_NAME.equals(cookie.getName())) {
                    return true;
                }
            }
        }
        return false;
    }

    private Claims validateToken(HttpServletRequest request) {
        // Obtener el token de las cookies
        for (Cookie cookie : request.getCookies()) {
            if (COOKIE_NAME.equals(cookie.getName())) {
                String jwtToken = cookie.getValue();
                return Jwts.parserBuilder()
                        .setSigningKey(Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8)))
                        .build()
                        .parseClaimsJws(jwtToken)
                        .getBody();
            }
        }
        throw new RuntimeException("Token not found or invalid");
    }

    private void setUpSpringAuthentication(Claims claims) {
        @SuppressWarnings("unchecked")
        List<String> authorities = (List<String>) claims.get("authorities");
        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                claims.getSubject(), null,
                authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
        SecurityContextHolder.getContext().setAuthentication(auth);
    }
}
