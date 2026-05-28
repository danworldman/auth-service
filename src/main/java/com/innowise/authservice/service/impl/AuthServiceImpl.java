package com.innowise.authservice.service.impl;

import com.innowise.authservice.dao.RefreshTokenDAO;
import com.innowise.authservice.dao.UserCredentialDAO;
import com.innowise.authservice.exception.InvalidRefreshTokenException;
import com.innowise.authservice.exception.UsernameAlreadyExistsException;
import com.innowise.authservice.mapper.UserCredentialMapper;
import com.innowise.authservice.model.dto.token.AuthenticationRequest;
import com.innowise.authservice.model.dto.token.RefreshTokenRequest;
import com.innowise.authservice.model.dto.token.TokenResponse;
import com.innowise.authservice.model.dto.token.ValidateResponse;
import com.innowise.authservice.model.dto.token.ValidateTokenRequest;
import com.innowise.authservice.model.dto.user.RegistrationRequest;
import com.innowise.authservice.model.dto.user.UserResponse;
import com.innowise.authservice.model.entity.RefreshToken;
import com.innowise.authservice.model.entity.UserCredential;
import com.innowise.authservice.security.JwtUtil;
import com.innowise.authservice.service.AuthService;
import java.time.LocalDateTime;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserCredentialDAO userCredentialDAO;
    private final RefreshTokenDAO refreshTokenDAO;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;
    private final UserCredentialMapper userCredentialMapper;

    @Override
    @Transactional
    public UserResponse registration(RegistrationRequest request) {
        if (userCredentialDAO.findByUsername(request.username()).isPresent()) {
            throw new UsernameAlreadyExistsException("Username already exists: " + request.username());
        }

        UserCredential user = userCredentialMapper.toEntity(request);
        user.setPasswordHash(passwordEncoder.encode(request.password()));

        UserCredential savedUser = userCredentialDAO.save(user);
        return userCredentialMapper.toResponse(savedUser);
    }

    @Override
    @Transactional
    public void rollbackCredentials(Long userServiceId) {
        UserCredential credential = userCredentialDAO.findByUserServiceId(userServiceId)
                .orElseThrow(() -> new EntityNotFoundException("User credentials not found for ID: " + userServiceId));
        userCredentialDAO.delete(credential);
    }

    @Override
    @Transactional
    public TokenResponse authentication(AuthenticationRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserCredential user = userCredentialDAO.findByUsername(request.username())
                .orElseThrow(() -> new RuntimeException("User not found"));

        UserDetails userDetails = userDetailsService.loadUserByUsername(request.username());

        String role = userDetails.getAuthorities()
                .stream()
                .findFirst()
                .map(GrantedAuthority::getAuthority)
                .map(auth -> auth.replace("ROLE_", ""))
                .orElseThrow(() -> new RuntimeException("User has no authorities"));

        String accessToken = jwtUtil.generateAccessToken(userDetails, user.getUserServiceId(), role);
        String refreshTokenStr = jwtUtil.generateRefreshToken(userDetails.getUsername());

        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setToken(refreshTokenStr);
        refreshTokenEntity.setUserCredential(user);
        refreshTokenEntity.setExpiryDate(LocalDateTime.now().plusDays(7));
        refreshTokenEntity.setRevoked(false);
        refreshTokenDAO.save(refreshTokenEntity);

        return new TokenResponse(accessToken, refreshTokenStr);
    }

    @Override
    @Transactional
    public TokenResponse refreshToken(RefreshTokenRequest refreshToken) {
        String token = refreshToken.refreshToken();
        RefreshToken storedToken = refreshTokenDAO.findByToken(token)
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token"));

        if (storedToken.isRevoked() || storedToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new InvalidRefreshTokenException("Refresh token expired or revoked");
        }

        UserCredential user = storedToken.getUserCredential();
        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        String newAccessToken = jwtUtil.generateAccessToken(userDetails, user.getUserServiceId(), user.getRole());

        return new TokenResponse(newAccessToken, token);
    }

    @Override
    @Transactional(readOnly = true)
    public ValidateResponse validateToken(ValidateTokenRequest accessToken) {
        String token = accessToken.token();

        if (jwtUtil.validateToken(token)) {
            String username = jwtUtil.extractUsername(token);
            String role = jwtUtil.extractRole(token);
            UserCredential user = userCredentialDAO.findByUsername(username).orElse(null);
            Long userServiceId = (user != null) ? user.getUserServiceId() : null;

            return new ValidateResponse(userServiceId, role);
        }

        return new ValidateResponse(null, null);
    }
}