package com.innowise.authservice.controller;

import com.innowise.authservice.model.dto.token.AuthenticationRequest;
import com.innowise.authservice.model.dto.token.RefreshTokenRequest;
import com.innowise.authservice.model.dto.token.TokenResponse;
import com.innowise.authservice.model.dto.token.ValidateResponse;
import com.innowise.authservice.model.dto.token.ValidateTokenRequest;
import com.innowise.authservice.model.dto.user.RegistrationRequest;
import com.innowise.authservice.model.dto.user.UserResponse;
import com.innowise.authservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller for authentication operations.
 * Provides endpoints for user registration, authentication, token refresh, validation, and rollback.
 */
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    /**
     * Registers new user credentials linked to an existing user profile in User Service.
     *
     * @param registrationRequest registration data (userServiceId, username, role, password)
     * @return created user credentials response
     */
    @PostMapping("/credentials")
    public ResponseEntity<UserResponse> registration(@Valid @RequestBody RegistrationRequest registrationRequest) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.registration(registrationRequest));
    }

    /**
     * Authenticates a user and issues JWT access and refresh tokens.
     *
     * @param authenticationRequest login credentials (username, password)
     * @return pair of access and refresh tokens
     */
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> authentication(@Valid @RequestBody AuthenticationRequest authenticationRequest) {
        return ResponseEntity.ok(authService.authentication(authenticationRequest));
    }

    /**
     * Refreshes an expired access token using a valid refresh token.
     *
     * @param refreshTokenRequest refresh token
     * @return new access token and the same refresh token
     */
    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest) {
        return ResponseEntity.ok(authService.refreshToken(refreshTokenRequest));
    }

    /**
     * Validates a JWT token and returns user ID and role extracted from its claims.
     *
     * @param validateTokenRequest token to validate
     * @return user ID and role, or null values if token is invalid
     */
    @PostMapping("/validate")
    public ResponseEntity<ValidateResponse> validate(@Valid @RequestBody ValidateTokenRequest validateTokenRequest) {
        return ResponseEntity.ok(authService.validateToken(validateTokenRequest));
    }

    /**
     * Deletes credentials associated with the given user service ID (rollback operation).
     *
     * @param userServiceId ID of the user in User Service
     * @return no content response
     */
    @DeleteMapping("/rollback/{userServiceId}")
    public ResponseEntity<Void> rollback(@PathVariable Long userServiceId) {
        authService.rollbackCredentials(userServiceId);
        return ResponseEntity.noContent().build();
    }
}