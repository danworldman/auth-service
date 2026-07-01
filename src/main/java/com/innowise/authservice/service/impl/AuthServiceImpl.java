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
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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

    @Value("${jwt.refresh-expiration}")
    private Long refreshExpirationMillis;

    @Override
    @Transactional
    public UserResponse registration(RegistrationRequest registrationRequest) {
        if (userCredentialDAO.findByUsername(registrationRequest.username()).isPresent()) {
            throw new UsernameAlreadyExistsException("Username already exists: " + registrationRequest.username());
        }

        UserCredential userCredential = userCredentialMapper.toEntity(registrationRequest);
        userCredential.setPasswordHash(passwordEncoder.encode(registrationRequest.password()));

        UserCredential savedUserCredential = userCredentialDAO.save(userCredential);
        return userCredentialMapper.toResponse(savedUserCredential);
    }

    @Override
    @Transactional
    public void rollbackCredentials(Long userServiceId) {
        userCredentialDAO.findByUserServiceId(userServiceId)
                .ifPresent(userCredentialDAO::delete);
    }

    @Override
    @Transactional
    public TokenResponse authentication(AuthenticationRequest authenticationRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(authenticationRequest.username(), authenticationRequest.password())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserCredential userCredential = userCredentialDAO.findByUsername(authenticationRequest.username())
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + authenticationRequest.username()));

        UserDetails userDetails = userDetailsService.loadUserByUsername(authenticationRequest.username());

        String securityRole = userDetails.getAuthorities()
                .stream()
                .findFirst()
                .map(GrantedAuthority::getAuthority)
                .map(authority -> authority.replace("ROLE_", ""))
                .orElseThrow(() -> new InsufficientAuthenticationException("User has no authorities"));

        String accessToken = jwtUtil.generateAccessToken(userDetails, userCredential.getUserServiceId(), securityRole);
        String generatedRefreshToken = UUID.randomUUID().toString();

        RefreshToken refreshTokenEntity = new RefreshToken();
        refreshTokenEntity.setToken(generatedRefreshToken);
        refreshTokenEntity.setUserCredential(userCredential);
        refreshTokenEntity.setExpiryDate(LocalDateTime.now().plus(refreshExpirationMillis, ChronoUnit.MILLIS));
        refreshTokenEntity.setRevoked(false);
        refreshTokenDAO.save(refreshTokenEntity);

        return new TokenResponse(accessToken, generatedRefreshToken);
    }

    @Override
    @Transactional
    public TokenResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {
        String refreshTokenValue = refreshTokenRequest.refreshToken();
        RefreshToken storedRefreshToken = refreshTokenDAO.findByToken(refreshTokenValue)
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token"));

        if (storedRefreshToken.isRevoked() || storedRefreshToken.getExpiryDate().isBefore(LocalDateTime.now())) {
            throw new InvalidRefreshTokenException("Refresh token expired or revoked");
        }

        UserCredential userCredential = storedRefreshToken.getUserCredential();
        UserDetails userDetails = userDetailsService.loadUserByUsername(userCredential.getUsername());

        String cleanSecurityRole = userCredential.getRole().replace("ROLE_", "");
        String newAccessToken = jwtUtil.generateAccessToken(userDetails, userCredential.getUserServiceId(), cleanSecurityRole);

        return new TokenResponse(newAccessToken, refreshTokenValue);
    }

    @Override
    @Transactional(readOnly = true)
    public ValidateResponse validateToken(ValidateTokenRequest validateTokenRequest) {
        String jsonWebToken = validateTokenRequest.token();
        if (jwtUtil.validateToken(jsonWebToken)) {
            Long userId = jwtUtil.extractUserId(jsonWebToken);
            String securityRole = jwtUtil.extractRole(jsonWebToken);
            return new ValidateResponse(userId, securityRole);
        }
        return new ValidateResponse(null, null);
    }
}