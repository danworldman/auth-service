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

    @PostMapping("/register")
    public ResponseEntity<UserResponse> register(@Valid @RequestBody RegistrationRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.registration(request));
    }

    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@Valid @RequestBody AuthenticationRequest request) {
        return ResponseEntity.ok(authService.authentication(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(authService.refreshToken(request));
    }

    @PostMapping("/validate")
    public ResponseEntity<ValidateResponse> validate(@Valid @RequestBody ValidateTokenRequest request) {
        return ResponseEntity.ok(authService.validateToken(request));
    }

    @DeleteMapping("/rollback/{userServiceId}")
    public ResponseEntity<Void> rollback(@PathVariable Long userServiceId) {
        authService.rollbackCredentials(userServiceId);
        return ResponseEntity.noContent().build();
    }
}