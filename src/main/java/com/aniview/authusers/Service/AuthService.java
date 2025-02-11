package com.aniview.authusers.Service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.aniview.authusers.Entity.Auth;
import com.aniview.authusers.Entity.User;
import com.aniview.authusers.Repository.AuthRepository;
import com.aniview.authusers.Repository.UserRepository;

import jakarta.transaction.Transactional;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final AuthRepository authRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthService(UserRepository userRepository, AuthRepository authRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.authRepository = authRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public boolean authenticate(String email, String password) {
        if (email == null || password == null)
            return false; // Evita NullPointerException

        User user = userRepository.findByEmail(email).orElse(null);
        if (user == null)
            return false;

        Auth auth = authRepository.findByUserId(user.getId()).orElse(null);
        return auth != null && passwordEncoder.matches(password, auth.getPassword());
    }

    @Transactional
    public User register(String email, String name, String lastname, String username, String image,
            String rawPassword) {
        // Verificar si el correo ya está registrado
        if (userRepository.findByEmail(email).isPresent()) {
            throw new IllegalArgumentException(
                    "El correo ya está registradoooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo");
        }

        // Crear y guardar el objeto User primero
        User newUser = new User(email, name, lastname, username, image);
        userRepository.save(newUser);

        // Encriptar la contraseña y luego crear el objeto Auth
        String encodedPassword = passwordEncoder.encode(rawPassword);
        Auth newAuth = new Auth(newUser, encodedPassword);

        // Guardar Auth después de guardar User
        authRepository.save(newAuth);

        return newUser;
    }

}
