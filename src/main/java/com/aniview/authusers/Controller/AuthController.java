package com.aniview.authusers.Controller;

import java.util.Collections;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority; // Importa el DTO
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.aniview.authusers.DTO.LoginRequest;
import com.aniview.authusers.DTO.RegisterRequest;
import com.aniview.authusers.Entity.User;
import com.aniview.authusers.Security.JWTUtil;
import com.aniview.authusers.Service.AuthService;
import com.aniview.authusers.Service.AuthTokenService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

@RestController
@RequestMapping("/auth")
public class AuthController {
    private final JWTUtil jwtUtil;
    private final AuthService authService;
    private final AuthTokenService authTokenService;

    // Inyección de dependencias por constructor
    public AuthController(JWTUtil jwtUtil, AuthService authService, AuthTokenService authTokenService) {
        this.jwtUtil = jwtUtil;
        this.authService = authService;
        this.authTokenService = authTokenService;
    }

    private static final String ROLE_USER = "ROLE_USER"; // Definimos la constante

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(HttpServletResponse response,
            @RequestBody LoginRequest loginRequest) { // Usa @RequestBody para recibir el objeto JSON
        String email = loginRequest.getEmail();
        String password = loginRequest.getPassword();

        if (authService.authenticate(email, password)) {
            String token = jwtUtil.createToken(email, Collections.singletonList(ROLE_USER));
            Cookie cookie = authTokenService.createAuthCookie(token);
            response.addCookie(cookie);
            return ResponseEntity.ok(Collections.singletonMap("message", "User " + email + " logged in successfully!"));
        } else {
            return ResponseEntity.status(401).body(Collections.singletonMap("message", "Invalid credentials"));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(HttpServletResponse response,
            @RequestBody RegisterRequest registerRequest) {
        try {
            // Paso 1: Registrar al usuario
            User newUser = authService.register(
                    registerRequest.getEmail(),
                    registerRequest.getName(),
                    registerRequest.getLastname(),
                    registerRequest.getUsername(),
                    registerRequest.getImage(),
                    registerRequest.getPassword());

            // Paso 2: Generar el token JWT
            String token = jwtUtil.createToken(newUser.getEmail(), Collections.singletonList(ROLE_USER));
            System.out.println("Generated Token: " + token); // Log para verificar el token

            // Paso 3: Crear la cookie de autenticación
            Cookie authCookie = authTokenService.createAuthCookie(token);

            // Paso 4: Establecer la cookie en la respuesta
            response.addCookie(authCookie); // Añadir la cookie en la respuesta

            // Paso 5: Establecer el contexto de seguridad para el usuario registrado
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    newUser.getEmail(), null, Collections.singletonList(new SimpleGrantedAuthority(ROLE_USER)));
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Paso 6: Responder con el mensaje de éxito
            return ResponseEntity.ok(Collections.singletonMap("message", "User registered successfully!"));

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Collections.singletonMap("message", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(500)
                    .body(Collections.singletonMap("message", "Server error: " + e.getMessage()));
        }
    }

    @GetMapping("/verify")
    public ResponseEntity<Map<String, String>> verifyToken(
            @CookieValue(value = "AUTH_TOKEN", required = false) String token) {
        if (token == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("message", "Token is missing"));
        }

        if (!jwtUtil.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("message", "Invalid token"));
        }

        // Si el token es válido, puedes devolver información adicional si lo deseas
        return ResponseEntity.ok(Collections.singletonMap("message", "Token is valid. Welcome!"));
    }
}
