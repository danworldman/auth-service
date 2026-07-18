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

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/credentials")
    public ResponseEntity<UserResponse> registration(@Valid @RequestBody RegistrationRequest registrationRequest) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.registration(registrationRequest));
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> authentication(@Valid @RequestBody AuthenticationRequest authenticationRequest) {
        return ResponseEntity.ok(authService.authentication(authenticationRequest));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshTokenRequest refreshTokenRequest) {
        return ResponseEntity.ok(authService.refreshToken(refreshTokenRequest));
    }

    @PostMapping("/validate")
    public ResponseEntity<ValidateResponse> validate(@Valid @RequestBody ValidateTokenRequest validateTokenRequest) {
        return ResponseEntity.ok(authService.validateToken(validateTokenRequest));
    }

    @DeleteMapping("/rollback/{userServiceId}")
    public ResponseEntity<Void> rollback(@PathVariable Long userServiceId) {
        authService.rollbackCredentials(userServiceId);
        return ResponseEntity.noContent().build();
    }
}