package com.aniview.authusers.security;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component // Asegúrate de que la clase sea un componente de Spring
public class JWTUtil {

    @Value("${jwt.secretKey}")
    private String secretKey; // Eliminar el static para poder inyectarlo correctamente

    private static final long EXPIRATION_TIME = 600_000; // 10 minutos
    private static final long REFRESH_TOKEN_EXPIRATION_TIME = 604_800_000;

    public String createToken(String username, List<String> roles) {
        if (secretKey == null || secretKey.isEmpty()) {
            throw new IllegalStateException("El secretKey no ha sido configurado.");
        }

        if (roles == null || roles.isEmpty()) {
            throw new IllegalArgumentException("Los roles no pueden estar vacíos.");
        }

        return Jwts.builder()
                .setSubject(username)
                .claim("authorities", roles)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)))
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return !claims.getExpiration().before(new Date());

        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // Crear Refresh Token
    public String createRefreshToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + REFRESH_TOKEN_EXPIRATION_TIME)) // 7 días
                .signWith(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)))
                .compact();
    }

    // Validar Refresh Token
    public boolean validateRefreshToken(String token) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)))
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            return !claims.getExpiration().before(new Date());

        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public String getUsernameFromRefreshToken(String refreshToken) {
        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)))
                    .build()
                    .parseClaimsJws(refreshToken)
                    .getBody();

            return claims.getSubject(); // Extraer el nombre de usuario del token

        } catch (JwtException | IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid or expired refresh token");
        }
    }

}
