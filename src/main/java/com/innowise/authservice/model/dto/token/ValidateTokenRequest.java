package com.innowise.authservice.model.dto.token;

import jakarta.validation.constraints.NotBlank;

public record ValidateTokenRequest(
        @NotBlank(message = "Token is required")
        String token
) {}