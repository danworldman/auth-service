package com.innowise.authservice.integration;

import com.innowise.authservice.model.dto.token.TokenResponse;
import com.innowise.authservice.model.dto.token.ValidateResponse;
import com.innowise.authservice.model.dto.user.RegistrationRequest;
import com.innowise.authservice.model.dto.user.UserResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class AuthControllerIntegrationTest extends BaseIntegrationTest {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private RestTemplate clientRestTemplate;

    @BeforeEach
    void setUp() {
        clientRestTemplate = new RestTemplate();
        clientRestTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse httpServletResponse) {
                return false;
            }
        });

        jdbcTemplate.execute("TRUNCATE TABLE refresh_tokens RESTART IDENTITY CASCADE");
        jdbcTemplate.execute("TRUNCATE TABLE users_credentials RESTART IDENTITY CASCADE");
    }

    private String baseUrl() {
        return "http://localhost:" + port + "/api/v1/auth";
    }

    @Test
    void register_shouldReturnCreatedUser() {
        RegistrationRequest registrationRequest = defaultRegistrationRequest("testUser", "USER", "pass");
        ResponseEntity<UserResponse> registrationResponse = clientRestTemplate.postForEntity(
                baseUrl() + "/credentials", registrationRequest, UserResponse.class
        );

        assertThat(registrationResponse.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(registrationResponse.getBody()).isNotNull();
        assertThat(registrationResponse.getBody().username()).isEqualTo("testUser");
    }

    @Test
    void register_shouldReturnConflictWhenUsernameExists() {
        RegistrationRequest registrationRequest = defaultRegistrationRequest("duplicate", "USER", "pass");
        clientRestTemplate.postForEntity(baseUrl() + "/credentials", registrationRequest, UserResponse.class);

        ResponseEntity<ProblemDetail> conflictResponse = clientRestTemplate.postForEntity(
                baseUrl() + "/credentials", registrationRequest, ProblemDetail.class
        );

        assertThat(conflictResponse.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(conflictResponse.getBody()).isNotNull();
    }

    @Test
    void register_shouldReturnBadRequest_whenUsernameIsEmpty() {
        RegistrationRequest registrationRequest = registrationRequest(100L, "", "USER", "pass");

        ResponseEntity<ProblemDetail> badRequestResponse = clientRestTemplate.postForEntity(
                baseUrl() + "/credentials", registrationRequest, ProblemDetail.class
        );

        assertThat(badRequestResponse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void register_shouldReturnBadRequest_whenRoleIsInvalid() {
        Map<String, String> invalidPayloadRequest = Map.of(
                "userServiceId", "200",
                "username", "validUser",
                "role", "INVALID_ROLE",
                "password", "pass"
        );

        ResponseEntity<ProblemDetail> badRequestResponse = clientRestTemplate.postForEntity(
                baseUrl() + "/credentials", invalidPayloadRequest, ProblemDetail.class
        );

        assertThat(badRequestResponse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(badRequestResponse.getBody()).isNotNull();
        assertThat(badRequestResponse.getBody().getDetail()).contains("Validation failed");
    }

    @Test
    void register_shouldReturnBadRequest_whenUnexpectedDeserializationExceptionOccurs() {
        Map<String, Object> corruptedPayloadRequest = Map.of(
                "userServiceId", "not-a-number-causes-error",
                "username", "user",
                "role", "USER",
                "password", "pass"
        );

        ResponseEntity<ProblemDetail> badRequestResponse = clientRestTemplate.postForEntity(
                baseUrl() + "/credentials", corruptedPayloadRequest, ProblemDetail.class
        );

        assertThat(badRequestResponse.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(badRequestResponse.getBody()).isNotNull();
    }

    @Test
    void login_shouldReturnTokensWhenCredentialsValid() {
        RegistrationRequest registrationRequest = defaultRegistrationRequest("loginUser", "USER", "pass");
        clientRestTemplate.postForEntity(baseUrl() + "/credentials", registrationRequest, UserResponse.class);

        Map<String, String> loginPayloadRequest = loginRequest("loginUser", "pass");
        ResponseEntity<TokenResponse> loginResponse = clientRestTemplate.postForEntity(
                baseUrl() + "/login", loginPayloadRequest, TokenResponse.class
        );

        assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(loginResponse.getBody()).isNotNull();
        assertThat(loginResponse.getBody().accessToken()).isNotBlank();
        assertThat(loginResponse.getBody().refreshToken()).isNotBlank();
    }

    @Test
    void login_shouldReturnUnauthorizedWhenInvalidCredentials() {
        RegistrationRequest registrationRequest = defaultRegistrationRequest("wrongPassUser", "USER", "correct");
        clientRestTemplate.postForEntity(baseUrl() + "/credentials", registrationRequest, UserResponse.class);

        Map<String, String> loginPayloadRequest = loginRequest("wrongPassUser", "incorrect");
        ResponseEntity<ProblemDetail> unauthorizedResponse = clientRestTemplate.postForEntity(
                baseUrl() + "/login", loginPayloadRequest, ProblemDetail.class
        );

        assertThat(unauthorizedResponse.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void validate_shouldReturnUserIdAndRoleForValidToken() {
        RegistrationRequest registrationRequest = defaultRegistrationRequest("validateUser", "ADMIN", "pass");
        clientRestTemplate.postForEntity(baseUrl() + "/credentials", registrationRequest, UserResponse.class);

        Map<String, String> loginPayloadRequest = loginRequest("validateUser", "pass");
        TokenResponse tokenResponse = clientRestTemplate.postForEntity(
                baseUrl() + "/login", loginPayloadRequest, TokenResponse.class
        ).getBody();

        assertNotNull(tokenResponse);
        Map<String, String> validatePayloadRequest = tokenRequest(tokenResponse.accessToken());
        ResponseEntity<ValidateResponse> validateResponse = clientRestTemplate.postForEntity(
                baseUrl() + "/validate", validatePayloadRequest, ValidateResponse.class
        );

        assertThat(validateResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(validateResponse.getBody()).isNotNull();
        assertThat(validateResponse.getBody().userId()).isPositive();
        assertThat(validateResponse.getBody().role()).isEqualTo("ADMIN");
    }

    @Test
    void validate_shouldReturnNullForInvalidToken() {
        Map<String, String> validatePayloadRequest = tokenRequest("invalid.token.value");
        ResponseEntity<ValidateResponse> validateResponse = clientRestTemplate.postForEntity(
                baseUrl() + "/validate", validatePayloadRequest, ValidateResponse.class
        );

        assertThat(validateResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(validateResponse.getBody()).isNotNull();
        assertThat(validateResponse.getBody().userId()).isNull();
        assertThat(validateResponse.getBody().role()).isNull();
    }

    @Test
    void refresh_shouldReturnNewAccessToken() {
        RegistrationRequest registrationRequest = defaultRegistrationRequest("refreshUser", "USER", "pass");
        clientRestTemplate.postForEntity(baseUrl() + "/credentials", registrationRequest, UserResponse.class);

        Map<String, String> loginPayloadRequest = loginRequest("refreshUser", "pass");
        TokenResponse tokenResponse = clientRestTemplate.postForEntity(
                baseUrl() + "/login", loginPayloadRequest, TokenResponse.class
        ).getBody();

        assertNotNull(tokenResponse);
        Map<String, String> refreshPayloadRequest = refreshRequest(tokenResponse.refreshToken());
        ResponseEntity<TokenResponse> refreshResponse = clientRestTemplate.postForEntity(
                baseUrl() + "/refresh", refreshPayloadRequest, TokenResponse.class
        );

        assertThat(refreshResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(refreshResponse.getBody()).isNotNull();
        assertThat(refreshResponse.getBody().accessToken()).isNotBlank();
        assertThat(refreshResponse.getBody().refreshToken()).isEqualTo(tokenResponse.refreshToken());
    }

    @Test
    void refresh_shouldReturnUnauthorizedWhenTokenInvalid() {
        Map<String, String> refreshPayloadRequest = refreshRequest("invalid.refresh.token");
        ResponseEntity<ProblemDetail> unauthorizedResponse = clientRestTemplate.postForEntity(
                baseUrl() + "/refresh", refreshPayloadRequest, ProblemDetail.class
        );

        assertThat(unauthorizedResponse.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        if (unauthorizedResponse.getBody() != null) {
            assertThat(unauthorizedResponse.getBody().getDetail()).contains("Invalid refresh token");
        }
    }

    @Test
    void rollback_shouldDeleteCredentialsSuccessfully() {
        RegistrationRequest registrationRequest = registrationRequest(150L, "rollbackUser", "USER", "pass");
        clientRestTemplate.postForEntity(baseUrl() + "/credentials", registrationRequest, UserResponse.class);

        ResponseEntity<Void> rollbackResponse = clientRestTemplate.exchange(
                baseUrl() + "/rollback/150",
                HttpMethod.DELETE,
                null,
                Void.class
        );

        assertThat(rollbackResponse.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        Map<String, String> loginPayloadRequest = loginRequest("rollbackUser", "pass");
        ResponseEntity<ProblemDetail> loginResponse = clientRestTemplate.postForEntity(
                baseUrl() + "/login", loginPayloadRequest, ProblemDetail.class
        );

        assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void rollback_shouldReturnNotFoundWhenUserDoesNotExist() {
        ResponseEntity<ProblemDetail> notFoundResponse = clientRestTemplate.exchange(
                baseUrl() + "/rollback/999",
                HttpMethod.DELETE,
                null,
                ProblemDetail.class
        );

        assertThat(notFoundResponse.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(notFoundResponse.getBody()).isNotNull();
        assertThat(notFoundResponse.getBody().getDetail()).contains("User credentials not found");
    }

    private RegistrationRequest registrationRequest(Long userServiceId, String username, String role, String password) {
        return new RegistrationRequest(userServiceId, username, role, password);
    }

    private RegistrationRequest defaultRegistrationRequest(String username, String role, String password) {
        return registrationRequest(100L, username, role, password);
    }

    private Map<String, String> loginRequest(String username, String password) {
        return Map.of("username", username, "password", password);
    }

    private Map<String, String> tokenRequest(String token) {
        return Map.of("token", token);
    }

    private Map<String, String> refreshRequest(String refreshToken) {
        return Map.of("refreshToken", refreshToken);
    }
}