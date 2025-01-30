package com.aniview.authusers.Repository;

import com.aniview.authusers.Entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> { // Cambiar Long por UUID
    Optional<User> findByEmail(String email);
}
