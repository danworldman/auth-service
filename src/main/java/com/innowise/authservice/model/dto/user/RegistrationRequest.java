package com.innowise.authservice.model.dto.user;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record RegistrationRequest(
        @NotBlank(message = "Username is required")
        String username,

        @NotBlank(message = "Role is required")
        @Pattern(regexp = "ADMIN|USER", message = "Role must be ADMIN or USER")
        String role,

        @NotBlank(message = "Password is required")
        String password
) {}