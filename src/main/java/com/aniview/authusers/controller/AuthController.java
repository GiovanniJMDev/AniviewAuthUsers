package com.aniview.authusers.controller;

import java.util.Collections;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody; // Importa el DTO
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.aniview.authusers.dto.LoginRequestDto;
import com.aniview.authusers.dto.RegisterRequestDto;
import com.aniview.authusers.entity.User;
import com.aniview.authusers.security.JWTUtil;
import com.aniview.authusers.service.AuthService;
import com.aniview.authusers.service.AuthTokenService;

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

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    private static final String ROLE_USER = "ROLE_USER";
    private static final String MESSAGE_KEY = "message";

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(HttpServletResponse response,
            @RequestBody LoginRequestDto loginRequest) {
        String email = loginRequest.email();
        String password = loginRequest.password();

        if (authService.authenticate(email, password)) {
            String token = jwtUtil.createToken(email, Collections.singletonList(ROLE_USER));
            String refreshToken = jwtUtil.createRefreshToken(email);

            // Devuelve el Access Token y Refresh Token al cliente
            return ResponseEntity.ok(Map.of(
                    "access_token", token,
                    "refresh_token", refreshToken));
        } else {
            return ResponseEntity.status(401).body(Collections.singletonMap(MESSAGE_KEY, "Invalid credentials"));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(@RequestBody RegisterRequestDto registerRequestDto) {
        try {
            // Paso 1: Registrar al usuario
            User newUser = authService.register(
                    registerRequestDto.email(),
                    registerRequestDto.name(),
                    registerRequestDto.lastname(),
                    registerRequestDto.username(),
                    registerRequestDto.image(),
                    registerRequestDto.password());

            // Crear Access Token y Refresh Token
            String token = jwtUtil.createToken(newUser.getEmail(), Collections.singletonList(ROLE_USER));
            String refreshToken = jwtUtil.createRefreshToken(newUser.getEmail()); // Agrega el Refresh Token

            // Devuelve el Access Token y el Refresh Token en la respuesta
            return ResponseEntity.ok(Map.of(
                    "access_token", token,
                    "refresh_token", refreshToken));

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Collections.singletonMap(MESSAGE_KEY, e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(500)
                    .body(Collections.singletonMap(MESSAGE_KEY, "Server error: " + e.getMessage()));
        }
    }

    @GetMapping("/verify")
    public ResponseEntity<Map<String, String>> verifyToken(
            @RequestHeader(value = "Authorization") String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap(MESSAGE_KEY, "Token is missing or invalid"));
        }

        String token = authorizationHeader.substring(7);
        if (!jwtUtil.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap(MESSAGE_KEY, "Invalid token"));
        }

        // Si el token es válido, puedes devolver información adicional si lo deseas
        return ResponseEntity.ok(Collections.singletonMap(MESSAGE_KEY, "Token is valid. Welcome!"));
    }

    @PostMapping("/refresh")
    public ResponseEntity<Map<String, String>> refreshToken(@RequestBody Map<String, String> body) {
        String refreshToken = body.get("refresh_token");

        if (refreshToken == null || !jwtUtil.validateRefreshToken(refreshToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap(MESSAGE_KEY, "Invalid or expired refresh token"));
        }

        String username = jwtUtil.getUsernameFromRefreshToken(refreshToken); // Método en JWTUtil

        String newAccessToken = jwtUtil.createToken(username, Collections.singletonList(ROLE_USER));
        return ResponseEntity.ok(Collections.singletonMap("access_token", newAccessToken));
    }

}
