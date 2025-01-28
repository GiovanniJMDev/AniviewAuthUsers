package com.aniview.authusers.Controller;

import com.aniview.authusers.Service.AuthTokenService; // Importa el servicio corregido
import com.aniview.authusers.Security.JWTUtil; // Asumiendo que este es tu utilitario para JWT
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Collections;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthTokenService authTokenService; // Inyección del servicio correcto

    @PostMapping("/login")
    public ResponseEntity<?> login(HttpServletResponse response, @RequestParam("user") String username,
            @RequestParam("password") String password) {
        String token = JWTUtil.createToken(username, Collections.singletonList("ROLE_USER"));
        Cookie cookie = authTokenService.createAuthCookie(token);
        response.addCookie(cookie); // Añade la cookie directamente

        String successMessage = "User " + username + " logged in successfully!";
        return ResponseEntity.ok(Collections.singletonMap("message", successMessage));
    }

    // Método para verificar el token en la cookie y devolver un mensaje
    @GetMapping("/verify")
    public ResponseEntity<?> verifyToken(HttpServletRequest request) {
        // Obtener la cookie de la solicitud
        Cookie[] cookies = request.getCookies();

        // Obtener el token usando el servicio
        String token = authTokenService.getTokenFromCookie(cookies);

        if (token == null) {
            return ResponseEntity.status(401)
                    .body(Collections.singletonMap("message", "No token found, please login first."));
        }

        // Validar el token (usando tu clase JWTUtil)
        boolean isValid = JWTUtil.validateToken(token); // Aquí necesitas un método que valide el token (crea uno en
                                                        // JWTUtil)

        if (!isValid) {
            return ResponseEntity.status(401)
                    .body(Collections.singletonMap("message", "Invalid token. Please login again."));
        }

        // Si el token es válido, devolver el mensaje de éxito
        return ResponseEntity.ok(Collections.singletonMap("message", "Token is valid. Welcome!"));
    }

}
