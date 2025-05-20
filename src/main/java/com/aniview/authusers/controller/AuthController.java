package com.aniview.authusers.controller;

import java.util.Collections;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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

import com.aniview.authusers.dto.LoginRequestDto;
import com.aniview.authusers.dto.RegisterRequestDto;
import com.aniview.authusers.entity.User;
import com.aniview.authusers.security.JWTUtil;
import com.aniview.authusers.service.AuthService;
import com.aniview.authusers.service.AuthTokenService;

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
            Cookie cookie = authTokenService.createAuthCookie(token);
            response.addCookie(cookie);
            return ResponseEntity
                    .ok(Collections.singletonMap(MESSAGE_KEY, "User " + email + " logged in successfully!"));
        } else {
            return ResponseEntity.status(401).body(Collections.singletonMap(MESSAGE_KEY, "Invalid credentials"));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<Map<String, String>> register(HttpServletResponse response,
            @RequestBody RegisterRequestDto registerRequestDto) {
        try {
            // Paso 1: Registrar al usuario
            User newUser = authService.register(
                    registerRequestDto.email(),
                    registerRequestDto.name(),
                    registerRequestDto.lastname(),
                    registerRequestDto.username(),
                    registerRequestDto.image(),
                    registerRequestDto.password());

            String token = jwtUtil.createToken(newUser.getEmail(), Collections.singletonList(ROLE_USER));
            log.info("Generated Token: {}", token);

            Cookie authCookie = authTokenService.createAuthCookie(token);

            response.addCookie(authCookie);

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                    newUser.getEmail(), null, Collections.singletonList(new SimpleGrantedAuthority(ROLE_USER)));
            SecurityContextHolder.getContext().setAuthentication(authentication);

            return ResponseEntity.ok(Collections.singletonMap(MESSAGE_KEY, "User registered successfully!"));

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Collections.singletonMap(MESSAGE_KEY, e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(500)
                    .body(Collections.singletonMap(MESSAGE_KEY, "Server error: " + e.getMessage()));
        }
    }

    @GetMapping("/verify")
    public ResponseEntity<Map<String, String>> verifyToken(
            @CookieValue(value = "AUTH_TOKEN", required = false) String token) {
        if (token == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap(MESSAGE_KEY, "Token is missing"));
        }

        if (!jwtUtil.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap(MESSAGE_KEY, "Invalid token"));
        }

        // Si el token es válido, puedes devolver información adicional si lo deseas
        return ResponseEntity.ok(Collections.singletonMap(MESSAGE_KEY, "Token is valid. Welcome!"));
    }
}
