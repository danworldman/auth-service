package com.innowise.authservice.dao;

import com.innowise.authservice.model.entity.UserCredential;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserCredentialDAO extends JpaRepository<UserCredential, Long> {

    Optional<UserCredential> findByUsername(String name);

    Optional<UserCredential> findByUserServiceId(Long userServiceId);
}