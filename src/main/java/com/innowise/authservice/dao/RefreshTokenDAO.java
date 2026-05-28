package com.innowise.authservice.dao;

import com.innowise.authservice.model.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RefreshTokenDAO extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByToken(String token);
}