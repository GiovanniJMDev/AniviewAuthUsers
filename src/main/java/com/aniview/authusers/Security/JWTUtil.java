package com.aniview.authusers.Security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

public class JWTUtil {

    private static final String SECRET_KEY = "mySecretKey123456789012345678901234567890";
    private static final long EXPIRATION_TIME = 600_000; // 10 minutos

    public static String createToken(String username, List<String> roles) {
        return Jwts.builder()
                .setSubject(username)
                .claim("authorities", roles)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8)))
                .compact();
    }

    public static boolean validateToken(String token) {
        try {
            // Construir el JwtParser usando Jwts.parserBuilder()
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(Keys.hmacShaKeyFor(SECRET_KEY.getBytes(StandardCharsets.UTF_8))) // Clave segura
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