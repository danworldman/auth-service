package com.innowise.authservice.model.dto.token;

public record AuthenticationRequest (

        String username,

        String password
) {}