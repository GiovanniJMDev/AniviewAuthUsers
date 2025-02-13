package com.aniview.authusers.security;

import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component // Asegúrate de que la clase sea un componente de Spring
public class JWTUtil {

    @Value("${jwt.secretKey}")
    private String secretKey; // Eliminar el static para poder inyectarlo correctamente

    private static final long EXPIRATION_TIME = 600_000; // 10 minutos

    public String createToken(String username, List<String> roles) {
        if (secretKey == null || secretKey.isEmpty()) {
            throw new IllegalStateException("El secretKey no ha sido configurado.");
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
            // Construir el JwtParser usando Jwts.parserBuilder()
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8))) // Clave segura
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            return !claims.getExpiration().before(new Date()); // Verifica que el token no haya expirado
        } catch (Exception e) {
            // Si hay un error al decodificar o verificar el token, se considera inválido
            return false;
        }
    }
}
