package com.aniview.authusers.repository;

import java.util.Optional;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.aniview.authusers.entity.Auth;

@Repository
public interface AuthRepository extends JpaRepository<Auth, UUID> {

    Optional<Auth> findByUserId(UUID userId); // Nota el cambio en el nombre del método
}
