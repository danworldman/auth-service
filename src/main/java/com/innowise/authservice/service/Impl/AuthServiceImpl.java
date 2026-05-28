package com.innowise.authservice.service.Impl;

import com.innowise.authservice.exception.InvalidRefreshTokenException;
import com.innowise.authservice.exception.UsernameAlreadyExistsException;
import com.innowise.authservice.model.dto.token.*;
import com.innowise.authservice.model.dto.user.RegistrationRequest;
import com.innowise.authservice.model.dto.user.UserResponse;
import com.innowise.authservice.model.entity.RefreshToken;
import com.innowise.authservice.model.entity.UserCredential;
import com.innowise.authservice.dao.RefreshTokenDAO;
import com.innowise.authservice.dao.UserCredentialDAO;
import com.innowise.authservice.security.JwtUtil;
import com.innowise.authservice.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {

    private final UserCredentialDAO userCredentialDAO;
    private final RefreshTokenDAO refreshTokenDAO;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final UserDetailsService userDetailsService;

    @Override
    @Transactional
    public UserResponse registration(RegistrationRequest request) {
        if (userCredentialDAO.findByUsername(request.username()).isPresent()) {
            throw new UsernameAlreadyExistsException("Username already exists");
        }

        UserCredential user = new UserCredential();
        user.setUsername(request.username());
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setRole(request.role());
        user.setActive(true);
        user = userCredentialDAO.save(user);

        return new UserResponse(user.getId(), user.getUsername(), user.getRole(), user.isActive(),
                user.getCreatedAt(), user.getUpdatedAt());
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

        String role = userDetails.getAuthorities().stream()
                .findFirst()
                .map(a -> a.getAuthority().replace("ROLE_", ""))
                .orElseThrow(() -> new RuntimeException("User has no authorities"));

        String accessToken = jwtUtil.generateAccessToken(userDetails, user.getId(), role);
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
        String newAccessToken = jwtUtil.generateAccessToken(userDetails, user.getId(), user.getRole());

        return new TokenResponse(newAccessToken, token);
    }

    @Override
    @Transactional
    public ValidateResponse validateToken(ValidateTokenRequest accessToken) {
        String token = accessToken.token();
        if (jwtUtil.validateToken(token)) {
            String username = jwtUtil.extractUsername(token);
            String role = jwtUtil.extractRole(token);
            UserCredential user = userCredentialDAO.findByUsername(username).orElse(null);
            Long userId = (user != null) ? user.getId() : null;

            return new ValidateResponse(userId, role);
        }

        return new ValidateResponse(null, null);
    }
}