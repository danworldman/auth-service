package com.innowise.authservice.model.dto.token;

public record TokenResponse(
        String accessToken,
        String refreshToken
) {}