package com.innowise.authservice.model.dto.user;

import java.time.LocalDateTime;

public record UserResponse(
        Long id,
        String username,
        String role,
        boolean isActive,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {}