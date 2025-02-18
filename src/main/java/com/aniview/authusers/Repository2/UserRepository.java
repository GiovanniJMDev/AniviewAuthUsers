package com.aniview.authusers.Repository2;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import com.aniview.authusers.entity.User;

public interface UserRepository extends JpaRepository<User, UUID> { // Cambiar Long por UUID
    Optional<User> findByEmail(String email);
}
