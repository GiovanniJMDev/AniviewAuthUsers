package com.aniview.authusers;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.mockito.ArgumentMatchers.any;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.MockitoAnnotations;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.aniview.authusers.entity.Auth;
import com.aniview.authusers.entity.User;
import com.aniview.authusers.repository.AuthRepository;
import com.aniview.authusers.repository.UserRepository;
import com.aniview.authusers.service.AuthService;

class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private AuthRepository authRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @InjectMocks
    private AuthService authService;

    private User user;
    private Auth auth;
    private final String rawPassword = "password123";
    private final String encodedPassword = "encodedPassword";

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        user = new User("test@example.com", "John", "Doe", "johndoe", "image_url");
        auth = new Auth(user, encodedPassword);
    }

    @Test
    void testAuthenticate_Success() {
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));
        when(authRepository.findByUserId(user.getId())).thenReturn(Optional.of(auth));
        when(passwordEncoder.matches(rawPassword, encodedPassword)).thenReturn(true);

        assertTrue(authService.authenticate("test@example.com", rawPassword));
    }

    @Test
    void testAuthenticate_Failure_WrongPassword() {
        when(userRepository.findByEmail("test@example.com")).thenReturn(Optional.of(user));
        when(authRepository.findByUserId(user.getId())).thenReturn(Optional.of(auth));
        when(passwordEncoder.matches(rawPassword, encodedPassword)).thenReturn(false);

        assertFalse(authService.authenticate("test@example.com", rawPassword));
    }

    @Test
    void testAuthenticate_Failure_UserNotFound() {
        when(userRepository.findByEmail("unknown@example.com")).thenReturn(Optional.empty());
        assertFalse(authService.authenticate("unknown@example.com", rawPassword));
    }

    @Test
    void testRegister_Success() {
        when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.empty());
        when(passwordEncoder.encode(rawPassword)).thenReturn(encodedPassword);

        User registeredUser = authService.register(user.getEmail(), user.getName(), user.getLastname(),
                user.getUsername(), user.getImage(), rawPassword);

        assertNotNull(registeredUser);
        verify(userRepository, times(1)).save(any(User.class));
        verify(authRepository, times(1)).save(any(Auth.class));
    }

    @Test
    void testRegister_Failure_EmailAlreadyExists() {
        when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.of(user));

        Exception exception = assertThrows(IllegalArgumentException.class, () -> {
            authService.register(user.getEmail(), user.getName(), user.getLastname(),
                    user.getUsername(), user.getImage(), rawPassword);
        });

        assertEquals(
                "El correo ya está registrado",
                exception.getMessage());
    }
}
