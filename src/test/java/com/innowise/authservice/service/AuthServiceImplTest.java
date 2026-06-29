package com.innowise.authservice.service;

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
import com.innowise.authservice.service.impl.AuthServiceImpl;
import jakarta.persistence.EntityNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceImplTest {

    private static final LocalDateTime FIXED_DATE_TIME = LocalDateTime.of(2026, 5, 19, 3, 1);
    private static final Long USER_SERVICE_ID = 1L;

    @Mock
    private UserCredentialDAO userCredentialDAO;

    @Mock
    private RefreshTokenDAO refreshTokenDAO;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private UserDetailsService userDetailsService;

    @Mock
    private UserCredentialMapper userCredentialMapper;

    @InjectMocks
    private AuthServiceImpl authService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "refreshExpirationMillis", 604800000L);
    }

    @Test
    void registration_shouldReturnUserResponse_whenValid() {
        RegistrationRequest request = registrationRequest(2L, "Bob", "USER", "password");
        UserCredential userEntity = new UserCredential();
        UserCredential savedUser = userCredential(1L, "Bob", "USER", "encPass",
                true, 2L
        );

        UserResponse expectedResponse = userResponse(1L, "Bob", "USER", true);

        when(userCredentialDAO.findByUsername(request.username())).thenReturn(Optional.empty());
        when(userCredentialMapper.toEntity(request)).thenReturn(userEntity);
        when(passwordEncoder.encode(request.password())).thenReturn("encPass");
        when(userCredentialDAO.save(userEntity)).thenReturn(savedUser);
        when(userCredentialMapper.toResponse(savedUser)).thenReturn(expectedResponse);

        UserResponse response = authService.registration(request);

        assertEquals(1L, response.id());
        assertEquals("Bob", response.username());
        assertEquals("USER", response.role());
        assertTrue(response.isActive());
        verify(userCredentialDAO).findByUsername("Bob");
        verify(userCredentialDAO).save(userEntity);
    }

    @Test
    void registration_shouldReturnUserResponse_whenRoleAdmin() {
        RegistrationRequest request = registrationRequest(3L, "AdminUser", "ADMIN", "adminPass");
        UserCredential userEntity = new UserCredential();
        UserCredential savedUser = userCredential(2L, "AdminUser", "ADMIN", "encPass",
                true, 3L
        );

        UserResponse expectedResponse = userResponse(2L, "AdminUser", "ADMIN", true);

        when(userCredentialDAO.findByUsername(request.username())).thenReturn(Optional.empty());
        when(userCredentialMapper.toEntity(request)).thenReturn(userEntity);
        when(passwordEncoder.encode(request.password())).thenReturn("encPass");
        when(userCredentialDAO.save(userEntity)).thenReturn(savedUser);
        when(userCredentialMapper.toResponse(savedUser)).thenReturn(expectedResponse);

        UserResponse response = authService.registration(request);

        assertEquals("ADMIN", response.role());
    }

    @Test
    void registration_shouldThrowUsernameAlreadyExistsException_whenUsernameExists() {
        RegistrationRequest request = registrationRequest(4L, "Bob", "USER", "password");

        when(userCredentialDAO.findByUsername("Bob")).thenReturn(Optional.of(new UserCredential()));

        assertThrows(UsernameAlreadyExistsException.class, () -> authService.registration(request));
        verify(userCredentialDAO, never()).save(any());
    }

    @Test
    void rollbackCredentials_shouldDelete_whenUserExists() {
        UserCredential credential = new UserCredential();
        when(userCredentialDAO.findByUserServiceId(USER_SERVICE_ID)).thenReturn(Optional.of(credential));

        authService.rollbackCredentials(USER_SERVICE_ID);

        verify(userCredentialDAO).delete(credential);
    }

    @Test
    void rollbackCredentials_shouldThrowEntityNotFoundException_whenUserDoesNotExist() {
        when(userCredentialDAO.findByUserServiceId(USER_SERVICE_ID)).thenReturn(Optional.empty());

        assertThrows(EntityNotFoundException.class, () -> authService.rollbackCredentials(USER_SERVICE_ID));

        verify(userCredentialDAO, never()).delete(any());
    }

    @Test
    void authentication_shouldReturnTokenResponse_whenCredentialsValid() {
        AuthenticationRequest authenticationRequest = authenticationRequest("Bob", "password");
        Authentication authentication = mock(Authentication.class);
        UserCredential userCredential = userCredential(3L, "Bob", "USER", "encPass",
                true, USER_SERVICE_ID
        );

        UserDetails userDetails = new User("Bob", "encPass",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
        );

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(authentication);
        when(userCredentialDAO.findByUsername("Bob")).thenReturn(Optional.of(userCredential));
        when(userDetailsService.loadUserByUsername("Bob")).thenReturn(userDetails);
        when(jwtUtil.generateAccessToken(eq(userDetails), eq(USER_SERVICE_ID), eq("USER"))).thenReturn("access");

        TokenResponse tokenResponse = authService.authentication(authenticationRequest);

        assertNotNull(tokenResponse);
        assertEquals("access", tokenResponse.accessToken());
        assertNotNull(tokenResponse.refreshToken());
        assertEquals(36, tokenResponse.refreshToken().length());
        verify(refreshTokenDAO).save(any(RefreshToken.class));
    }

    @Test
    void authentication_shouldReturnTokenResponse_whenUserIsNotActive() {
        AuthenticationRequest request = authenticationRequest("inactiveUser", "pass");
        Authentication authentication = mock(Authentication.class);
        UserCredential user = userCredential(4L, "inactiveUser", "USER", "encPass",
                false, USER_SERVICE_ID
        );

        UserDetails userDetails = new User("inactiveUser", "encPass",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
        );

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(authentication);
        when(userCredentialDAO.findByUsername("inactiveUser")).thenReturn(Optional.of(user));
        when(userDetailsService.loadUserByUsername("inactiveUser")).thenReturn(userDetails);
        when(jwtUtil.generateAccessToken(eq(userDetails), eq(USER_SERVICE_ID), eq("USER"))).thenReturn("access");

        TokenResponse response = authService.authentication(request);

        assertNotNull(response.accessToken());
        assertNotNull(response.refreshToken());
    }

    @Test
    void authentication_shouldThrowException_whenUserNotFoundInDb() {
        AuthenticationRequest request = authenticationRequest("Bob", "password");
        Authentication authentication = mock(Authentication.class);

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(authentication);
        when(userCredentialDAO.findByUsername("Bob")).thenReturn(Optional.empty());

        assertThrows(RuntimeException.class, () -> authService.authentication(request));
    }

    @Test
    void authentication_shouldThrowException_whenUserHasNoAuthorities() {
        AuthenticationRequest request = authenticationRequest("Bob", "password");
        Authentication authentication = mock(Authentication.class);
        UserCredential user = userCredential(5L, "Bob", "USER", "encPass",
                true, USER_SERVICE_ID
        );

        UserDetails userDetails = new User("Bob", "encPass", Collections.emptyList());

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class))).thenReturn(authentication);
        when(userCredentialDAO.findByUsername("Bob")).thenReturn(Optional.of(user));
        when(userDetailsService.loadUserByUsername("Bob")).thenReturn(userDetails);

        assertThrows(RuntimeException.class, () -> authService.authentication(request));
    }

    @Test
    void authentication_shouldThrowException_whenUsernameIsEmpty() {
        AuthenticationRequest request = new AuthenticationRequest("", "password");

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Bad credentials"));

        assertThrows(AuthenticationException.class, () -> authService.authentication(request));
    }

    @Test
    void refreshToken_shouldReturnNewTokens_whenValid() {
        RefreshTokenRequest request = refreshTokenRequest("refresh");
        UserCredential user = userCredential(6L, "Bob", "USER", "enc",
                true, USER_SERVICE_ID
        );

        RefreshToken storedToken = new RefreshToken();
        storedToken.setToken("refresh");
        storedToken.setUserCredential(user);
        storedToken.setExpiryDate(LocalDateTime.of(2100, 1, 1, 0, 0));
        storedToken.setRevoked(false);
        UserDetails userDetails = new User("Bob", "enc",
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER"))
        );

        when(refreshTokenDAO.findByToken("refresh")).thenReturn(Optional.of(storedToken));
        when(userDetailsService.loadUserByUsername("Bob")).thenReturn(userDetails);
        when(jwtUtil.generateAccessToken(eq(userDetails), eq(USER_SERVICE_ID), eq("USER"))).thenReturn("new-access");

        TokenResponse response = authService.refreshToken(request);

        assertEquals("new-access", response.accessToken());
        assertEquals("refresh", response.refreshToken());
    }

    @Test
    void refreshToken_shouldThrowException_whenTokenNotFound() {
        RefreshTokenRequest request = refreshTokenRequest("invalid");

        when(refreshTokenDAO.findByToken("invalid")).thenReturn(Optional.empty());

        assertThrows(InvalidRefreshTokenException.class, () -> authService.refreshToken(request));
    }

    @Test
    void refreshToken_shouldThrowException_whenTokenRevoked() {
        RefreshTokenRequest request = refreshTokenRequest("revoked");
        RefreshToken storedToken = new RefreshToken();
        storedToken.setRevoked(true);

        when(refreshTokenDAO.findByToken("revoked")).thenReturn(Optional.of(storedToken));

        assertThrows(InvalidRefreshTokenException.class, () -> authService.refreshToken(request));
    }

    @Test
    void refreshToken_shouldThrowException_whenTokenExpired() {
        RefreshTokenRequest request = refreshTokenRequest("expired");
        RefreshToken storedToken = new RefreshToken();
        storedToken.setExpiryDate(FIXED_DATE_TIME);

        when(refreshTokenDAO.findByToken("expired")).thenReturn(Optional.of(storedToken));

        assertThrows(InvalidRefreshTokenException.class, () -> authService.refreshToken(request));
    }

    @Test
    void refreshToken_shouldThrowException_whenTokenIsExpiredInDb() {
        RefreshTokenRequest request = refreshTokenRequest("expired-token");
        UserCredential user = new UserCredential();
        RefreshToken storedToken = new RefreshToken();
        storedToken.setToken("expired-token");
        storedToken.setUserCredential(user);
        storedToken.setExpiryDate(FIXED_DATE_TIME);
        storedToken.setRevoked(false);

        when(refreshTokenDAO.findByToken("expired-token")).thenReturn(Optional.of(storedToken));

        assertThrows(InvalidRefreshTokenException.class, () -> authService.refreshToken(request));
    }

    @Test
    void validateToken_shouldReturnResponse_whenTokenValid() {
        ValidateTokenRequest request = validateTokenRequest("jwt");

        when(jwtUtil.validateToken("jwt")).thenReturn(true);
        when(jwtUtil.extractUserId("jwt")).thenReturn(USER_SERVICE_ID);
        when(jwtUtil.extractRole("jwt")).thenReturn("USER");

        ValidateResponse response = authService.validateToken(request);

        assertEquals(USER_SERVICE_ID, response.userId());
        assertEquals("USER", response.role());
    }

    @Test
    void validateToken_shouldReturnNullResponse_whenTokenInvalid() {
        ValidateTokenRequest request = validateTokenRequest("invalid-jwt");

        when(jwtUtil.validateToken("invalid-jwt")).thenReturn(false);

        ValidateResponse response = authService.validateToken(request);

        assertNull(response.userId());
        assertNull(response.role());
    }

    private RegistrationRequest registrationRequest(Long userServiceId, String username, String role, String password) {
        return new RegistrationRequest(userServiceId, username, role, password);
    }

    private AuthenticationRequest authenticationRequest(String username, String password) {
        return new AuthenticationRequest(username, password);
    }

    private RefreshTokenRequest refreshTokenRequest(String refreshToken) {
        return new RefreshTokenRequest(refreshToken);
    }

    private ValidateTokenRequest validateTokenRequest(String token) {
        return new ValidateTokenRequest(token);
    }

    private UserCredential userCredential(Long id, String username, String role, String passwordHash,
                                          boolean isActive, Long userServiceId) {
        return new UserCredential(id, username, role, passwordHash, isActive, userServiceId,
                FIXED_DATE_TIME, FIXED_DATE_TIME, Collections.emptyList());
    }

    private UserResponse userResponse(Long id, String username, String role, boolean isActive) {
        return new UserResponse(id, username, role, isActive, FIXED_DATE_TIME, FIXED_DATE_TIME);
    }
}