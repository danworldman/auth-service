package com.innowise.authservice.model.dto.token;

public record RefreshTokenRequest(
        String refreshToken
) {}