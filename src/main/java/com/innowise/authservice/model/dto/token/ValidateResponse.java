package com.innowise.authservice.model.dto.token;

public record ValidateResponse(
        Long userId,
        String role
) {}