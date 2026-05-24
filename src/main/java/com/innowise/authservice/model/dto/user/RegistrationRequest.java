package com.innowise.authservice.model.dto.user;

public record RegistrationRequest(

        String username,

        String role,

        String password
) {}