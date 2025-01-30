package com.aniview.authusers.Repository;

import com.aniview.authusers.Entity.Auth;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface AuthRepository extends JpaRepository<Auth, UUID> {
    Optional<Auth> findByUserId(UUID userId); // Nota el cambio en el nombre del método
}
