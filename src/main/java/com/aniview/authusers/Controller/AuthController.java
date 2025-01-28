package com.aniview.authusers.Controller;

import com.aniview.authusers.Service.AuthTokenService; // Importa el servicio corregido
import com.aniview.authusers.Security.JWTUtil; // Asumiendo que este es tu utilitario para JWT
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.Cookie;

import java.util.Collections;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthTokenService authTokenService; // Inyección del servicio correcto

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestParam("user") String username, @RequestParam("password") String password) {
        // Aquí validas el usuario y la contraseña (en este ejemplo no lo haces)

        // Generar el token JWT
        String token = JWTUtil.createToken(username, Collections.singletonList("ROLE_USER"));

        // Crear la cookie usando el servicio
        Cookie cookie = authTokenService.createAuthCookie(token);

        // Crear el mensaje de éxito
        String successMessage = "User " + username + " logged in successfully!";

        // Devolver la respuesta con la cookie y el mensaje
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE,
                        cookie.getName() + "=" + cookie.getValue() + "; Path=" + cookie.getPath() + "; Max-Age="
                                + cookie.getMaxAge() + "; HttpOnly; Secure")
                .body(Collections.singletonMap("message", successMessage)); // Mensaje de éxito en el cuerpo
    }
    
}
