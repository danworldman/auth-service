package com.innowise.authservice.service;

import com.innowise.authservice.model.dto.token.AuthenticationRequest;
import com.innowise.authservice.model.dto.token.RefreshTokenRequest;
import com.innowise.authservice.model.dto.token.TokenResponse;
import com.innowise.authservice.model.dto.token.ValidateResponse;
import com.innowise.authservice.model.dto.token.ValidateTokenRequest;
import com.innowise.authservice.model.dto.user.RegistrationRequest;
import com.innowise.authservice.model.dto.user.UserResponse;

/**
 * Service interface for authentication operations.
 */
public interface AuthService {

    /**
     * Registers user credentials linked to an existing user profile in User Service.
     *
     * @param request registration data (userServiceId, username, role, password)
     * @return saved user credentials response
     */
    UserResponse registration(RegistrationRequest request);

    /**
     * Authenticates a user and returns JWT access and refresh tokens.
     *
     * @param request login credentials (username, password)
     * @return pair of access and refresh tokens
     */
    TokenResponse authentication(AuthenticationRequest request);

    /**
     * Refreshes an expired access token using a valid refresh token.
     *
     * @param refreshToken request containing refresh token
     * @return new access token and the same refresh token
     */
    TokenResponse refreshToken(RefreshTokenRequest refreshToken);

    /**
     * Validates a JWT token and extracts user ID and role from its claims.
     *
     * @param accessToken request containing JWT token
     * @return user ID and role, or nulls if token is invalid
     */
    ValidateResponse validateToken(ValidateTokenRequest accessToken);

    /**
     * Deletes credentials associated with the given user service ID (rollback).
     *
     * @param userServiceId ID of the user in User Service
     */
    void rollbackCredentials(Long userServiceId);
}