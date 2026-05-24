package com.innowise.authservice.service;

import com.innowise.authservice.model.dto.token.AuthenticationRequest;
import com.innowise.authservice.model.dto.token.RefreshTokenRequest;
import com.innowise.authservice.model.dto.token.TokenResponse;
import com.innowise.authservice.model.dto.token.ValidateResponse;
import com.innowise.authservice.model.dto.token.ValidateTokenRequest;
import com.innowise.authservice.model.dto.user.RegistrationRequest;
import com.innowise.authservice.model.dto.user.UserResponse;

public interface AuthService {

    UserResponse registration(RegistrationRequest request);

    TokenResponse authentication(AuthenticationRequest request);

    TokenResponse refreshToken(RefreshTokenRequest refreshToken);

    ValidateResponse validateToken(ValidateTokenRequest accessToken);
}