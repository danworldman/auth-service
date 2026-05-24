package com.innowise.authservice.service.Impl;

import com.innowise.authservice.model.dto.token.AuthenticationRequest;
import com.innowise.authservice.model.dto.token.RefreshTokenRequest;
import com.innowise.authservice.model.dto.token.TokenResponse;
import com.innowise.authservice.model.dto.token.ValidateResponse;
import com.innowise.authservice.model.dto.token.ValidateTokenRequest;
import com.innowise.authservice.model.dto.user.RegistrationRequest;
import com.innowise.authservice.model.dto.user.UserResponse;
import com.innowise.authservice.service.AuthService;

public class AuthServiceImpl implements AuthService {
    @Override
    public UserResponse registration(RegistrationRequest request) {
        return null;
    }

    @Override
    public TokenResponse authentication(AuthenticationRequest request) {
        return null;
    }

    @Override
    public TokenResponse refreshToken(RefreshTokenRequest refreshToken) {
        return null;
    }

    @Override
    public ValidateResponse validateToken(ValidateTokenRequest accessToken) {
        return null;
    }
}