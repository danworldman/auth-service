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
            public boolean hasError(ClientHttpResponse response) {
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
        RegistrationRequest request = defaultRegistrationRequest("testUser", "USER", "pass");
        ResponseEntity<UserResponse> response = clientRestTemplate.postForEntity(
                baseUrl() + "/register", request, UserResponse.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().username()).isEqualTo("testUser");
    }

    @Test
    void register_shouldReturnConflictWhenUsernameExists() {
        RegistrationRequest request = defaultRegistrationRequest("duplicate", "USER", "pass");
        clientRestTemplate.postForEntity(baseUrl() + "/register", request, UserResponse.class);

        ResponseEntity<ProblemDetail> response = clientRestTemplate.postForEntity(
                baseUrl() + "/register", request, ProblemDetail.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody()).isNotNull();
    }

    @Test
    void register_shouldReturnBadRequest_whenUsernameIsEmpty() {
        RegistrationRequest request = registrationRequest(100L, "", "USER", "pass");

        ResponseEntity<ProblemDetail> response = clientRestTemplate.postForEntity(
                baseUrl() + "/register", request, ProblemDetail.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void register_shouldReturnBadRequest_whenRoleIsInvalid() {
        Map<String, String> invalidRequest = Map.of(
                "userServiceId", "200",
                "username", "validUser",
                "role", "INVALID_ROLE",
                "password", "pass"
        );

        ResponseEntity<ProblemDetail> response = clientRestTemplate.postForEntity(
                baseUrl() + "/register", invalidRequest, ProblemDetail.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getDetail()).contains("Validation failed");
    }

    @Test
    void register_shouldReturnBadRequest_whenUnexpectedDeserializationExceptionOccurs() {
        Map<String, Object> corruptedPayload = Map.of(
                "userServiceId", "not-a-number-causes-error",
                "username", "user",
                "role", "USER",
                "password", "pass"
        );

        ResponseEntity<ProblemDetail> response = clientRestTemplate.postForEntity(
                baseUrl() + "/register", corruptedPayload, ProblemDetail.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
    }


    @Test
    void login_shouldReturnTokensWhenCredentialsValid() {
        RegistrationRequest regRequest = defaultRegistrationRequest("loginUser", "USER", "pass");
        clientRestTemplate.postForEntity(baseUrl() + "/register", regRequest, UserResponse.class);

        Map<String, String> loginRequest = loginRequest("loginUser", "pass");
        ResponseEntity<TokenResponse> loginResponse = clientRestTemplate.postForEntity(
                baseUrl() + "/login", loginRequest, TokenResponse.class
        );

        assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(loginResponse.getBody()).isNotNull();
        assertThat(loginResponse.getBody().accessToken()).isNotBlank();
        assertThat(loginResponse.getBody().refreshToken()).isNotBlank();
    }

    @Test
    void login_shouldReturnUnauthorizedWhenInvalidCredentials() {
        RegistrationRequest regRequest = defaultRegistrationRequest("wrongPassUser", "USER", "correct");
        clientRestTemplate.postForEntity(baseUrl() + "/register", regRequest, UserResponse.class);

        Map<String, String> loginRequest = loginRequest("wrongPassUser", "incorrect");
        ResponseEntity<ProblemDetail> response = clientRestTemplate.postForEntity(
                baseUrl() + "/login", loginRequest, ProblemDetail.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void validate_shouldReturnUserIdAndRoleForValidToken() {
        RegistrationRequest regRequest = defaultRegistrationRequest("validateUser", "ADMIN", "pass");
        clientRestTemplate.postForEntity(baseUrl() + "/register", regRequest, UserResponse.class);

        Map<String, String> loginRequest = loginRequest("validateUser", "pass");
        TokenResponse tokens = clientRestTemplate.postForEntity(
                baseUrl() + "/login", loginRequest, TokenResponse.class
        ).getBody();

        assertNotNull(tokens);
        Map<String, String> validateRequest = tokenRequest(tokens.accessToken());
        ResponseEntity<ValidateResponse> validateResponse = clientRestTemplate.postForEntity(
                baseUrl() + "/validate", validateRequest, ValidateResponse.class
        );

        assertThat(validateResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(validateResponse.getBody()).isNotNull();
        assertThat(validateResponse.getBody().userId()).isPositive();
        assertThat(validateResponse.getBody().role()).isEqualTo("ADMIN");
    }

    @Test
    void validate_shouldReturnNullForInvalidToken() {
        Map<String, String> validateRequest = tokenRequest("invalid.token.value");
        ResponseEntity<ValidateResponse> response = clientRestTemplate.postForEntity(
                baseUrl() + "/validate", validateRequest, ValidateResponse.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().userId()).isNull();
        assertThat(response.getBody().role()).isNull();
    }

    @Test
    void refresh_shouldReturnNewAccessToken() {
        RegistrationRequest regRequest = defaultRegistrationRequest("refreshUser", "USER", "pass");
        clientRestTemplate.postForEntity(baseUrl() + "/register", regRequest, UserResponse.class);

        Map<String, String> loginRequest = loginRequest("refreshUser", "pass");
        TokenResponse tokens = clientRestTemplate.postForEntity(
                baseUrl() + "/login", loginRequest, TokenResponse.class
        ).getBody();

        assertNotNull(tokens);
        Map<String, String> refreshRequest = refreshRequest(tokens.refreshToken());
        ResponseEntity<TokenResponse> refreshResponse = clientRestTemplate.postForEntity(
                baseUrl() + "/refresh", refreshRequest, TokenResponse.class
        );

        assertThat(refreshResponse.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(refreshResponse.getBody()).isNotNull();
        assertThat(refreshResponse.getBody().accessToken()).isNotBlank();
        assertThat(refreshResponse.getBody().refreshToken()).isEqualTo(tokens.refreshToken());
    }

    @Test
    void refresh_shouldReturnUnauthorizedWhenTokenInvalid() {
        Map<String, String> refreshRequest = refreshRequest("invalid.refresh.token");
        ResponseEntity<ProblemDetail> response = clientRestTemplate.postForEntity(
                baseUrl() + "/refresh", refreshRequest, ProblemDetail.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        if (response.getBody() != null) {
            assertThat(response.getBody().getDetail()).contains("Invalid refresh token");
        }
    }

    @Test
    void rollback_shouldDeleteCredentialsSuccessfully() {
        RegistrationRequest regRequest = registrationRequest(150L, "rollbackUser", "USER", "pass");
        clientRestTemplate.postForEntity(baseUrl() + "/register", regRequest, UserResponse.class);

        ResponseEntity<Void> response = clientRestTemplate.exchange(
                baseUrl() + "/rollback/150",
                HttpMethod.DELETE,
                null,
                Void.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

        Map<String, String> loginRequest = loginRequest("rollbackUser", "pass");
        ResponseEntity<ProblemDetail> loginResponse = clientRestTemplate.postForEntity(
                baseUrl() + "/login", loginRequest, ProblemDetail.class
        );

        assertThat(loginResponse.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void rollback_shouldReturnNotFoundWhenUserDoesNotExist() {
        ResponseEntity<ProblemDetail> response = clientRestTemplate.exchange(
                baseUrl() + "/rollback/999",
                HttpMethod.DELETE,
                null,
                ProblemDetail.class
        );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getDetail()).contains("User credentials not found");
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