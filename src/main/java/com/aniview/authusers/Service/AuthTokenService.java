package com.aniview.authusers.Service;

import jakarta.servlet.http.Cookie;
import org.springframework.stereotype.Service;

@Service
public class AuthTokenService {

    private static final String COOKIE_NAME = "AUTH_TOKEN"; // Nombre de la cookie

    // Método para crear la cookie con el token
    public Cookie createAuthCookie(String token) {
        Cookie cookie = new Cookie(COOKIE_NAME, token);
        cookie.setHttpOnly(true); // Hace que la cookie sea inaccesible desde JavaScript
        // cookie.setSecure(true); // Asegúrate de usar HTTPS en producción para mayor
        cookie.setPath("/"); // Define la ruta a la cual se aplica la cookie
        cookie.setMaxAge(60 * 60 * 24); // Define el tiempo de expiración (en segundos)
        return cookie;
    }

    // Método para obtener el token de la cookie
    public String getTokenFromCookie(Cookie[] cookies) {
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (COOKIE_NAME.equals(cookie.getName())) {
                    return cookie.getValue(); // Retorna el valor del token
                }
            }
        }
        return null; // Si no se encuentra la cookie, retorna null
    }
}
