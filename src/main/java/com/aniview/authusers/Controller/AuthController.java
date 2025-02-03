package com.aniview.authusers.Controller;

import com.aniview.authusers.Service.AuthService;
import com.aniview.authusers.Service.AuthTokenService;
import com.aniview.authusers.Security.JWTUtil;
import com.aniview.authusers.Entity.User;
import com.aniview.authusers.DTO.LoginRequest; // Importa el DTO
import com.aniview.authusers.DTO.RegisterRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Collections;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private AuthTokenService authTokenService;

    @PostMapping("/login")
    public ResponseEntity<?> login(HttpServletResponse response,
            @RequestBody LoginRequest loginRequest) { // Usa @RequestBody para recibir el objeto JSON
        String email = loginRequest.getEmail();
        String password = loginRequest.getPassword();

        if (authService.authenticate(email, password)) {
            String token = JWTUtil.createToken(email, Collections.singletonList("ROLE_USER"));
            Cookie cookie = authTokenService.createAuthCookie(token);
            response.addCookie(cookie);
            return ResponseEntity.ok(Collections.singletonMap("message", "User " + email + " logged in successfully!"));
        } else {
            return ResponseEntity.status(401).body(Collections.singletonMap("message", "Invalid credentials"));
        }
    }

    // Endpoint para registrar un nuevo usuario
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest registerRequest) {
        try {
            // Llamamos al servicio para registrar al usuario con los datos recibidos en
            // JSON
            User newUser = authService.register(
                    registerRequest.getEmail(),
                    registerRequest.getName(),
                    registerRequest.getLastname(),
                    registerRequest.getUsername(),
                    registerRequest.getImage(),
                    registerRequest.getPassword());
            return ResponseEntity.ok(newUser); // Devuelve el usuario recién registrado
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().body(Collections.singletonMap("message", e.getMessage())); // En caso de
                                                                                                          // error (por
                                                                                                          // ejemplo,
                                                                                                          // correo ya
                                                                                                          // registrado)
        } catch (Exception e) {
            return ResponseEntity.status(500)
                    .body(Collections.singletonMap("message", "Error en el servidor: " + e.getMessage())); // Captura
                                                                                                           // cualquier
                                                                                                           // otra
                                                                                                           // excepción
                                                                                                           // no
                                                                                                           // esperada
        }
    }

    @GetMapping("/verify")
    public ResponseEntity<?> verifyToken(@CookieValue(value = "AUTH_TOKEN", required = false) String token) {
        if (token == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("message", "Token is missing"));
        }

        if (!JWTUtil.validateToken(token)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Collections.singletonMap("message", "Invalid token"));
        }

        // Si el token es válido, puedes devolver información adicional si lo deseas
        return ResponseEntity.ok(Collections.singletonMap("message", "Token is valid. Welcome!"));
    }
}
