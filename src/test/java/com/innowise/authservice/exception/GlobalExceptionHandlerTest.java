package com.innowise.authservice.exception;

import jakarta.persistence.EntityNotFoundException;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.validation.Path;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void handleUsernameAlreadyExists_shouldReturnConflict() {
        UsernameAlreadyExistsException exception = new UsernameAlreadyExistsException("User exists");

        ResponseEntity<ProblemDetail> response = handler.handleUsernameAlreadyExists(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getDetail()).isEqualTo("User exists");
    }

    @Test
    void handleInvalidRefreshToken_shouldReturnUnauthorized() {
        InvalidRefreshTokenException exception = new InvalidRefreshTokenException("Invalid token");

        ResponseEntity<ProblemDetail> response = handler.handleInvalidRefreshToken(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getDetail()).isEqualTo("Invalid token");
    }

    @Test
    void handleRuntimeException_shouldReturnBadRequest() {
        RuntimeException exception = new RuntimeException("Some error");

        ResponseEntity<ProblemDetail> response = handler.handleOtherRuntime(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getDetail()).isEqualTo("Some error");
    }

    @Test
    void handleAuthenticationException_shouldReturnUnauthorized() {
        AuthenticationException exception = mock(AuthenticationException.class);

        ResponseEntity<ProblemDetail> response = handler.handleAuthentication(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getDetail()).isEqualTo("Invalid username or password");
    }

    @Test
    void handleEntityNotFound_shouldReturnNotFound() {
        EntityNotFoundException exception = new EntityNotFoundException("User not found");

        ResponseEntity<ProblemDetail> response = handler.handleEntityNotFound(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getDetail()).isEqualTo("User credentials not found");
    }

    @Test
    void handleAccessDenied_shouldReturnForbidden() {
        AccessDeniedException exception = new AccessDeniedException("Access denied");

        ResponseEntity<ProblemDetail> response = handler.handleAccessDenied(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getDetail()).isEqualTo("Access denied");
    }

    @Test
    void handleConstraintViolation_shouldReturnBadRequestWithErrors() {
        ConstraintViolationException exception = mock(ConstraintViolationException.class);
        ConstraintViolation<?> violation = mock(ConstraintViolation.class);
        Path path = mock(Path.class);

        when(violation.getPropertyPath()).thenReturn(path);
        when(path.toString()).thenReturn("field");
        when(violation.getMessage()).thenReturn("must not be null");
        when(exception.getConstraintViolations()).thenReturn(Set.of(violation));

        ResponseEntity<ProblemDetail> response = handler.handleConstraintViolation(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getDetail()).isEqualTo("Validation failed");
        assertThat(response.getBody().getProperties()).containsKey("errors");

        Map<String, String> errors = (Map<String, String>) response.getBody().getProperties().get("errors");
        assertThat(errors).containsEntry("field", "must not be null");
    }

    @Test
    void handleNoHandlerFound_shouldReturnNotFound() {
        NoHandlerFoundException exception = new NoHandlerFoundException("GET", "/notfound", null);

        ResponseEntity<ProblemDetail> response = handler.handleNotFound(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getDetail()).isEqualTo("Endpoint not found");
    }

    @Test
    void handleGlobalException_shouldReturnInternalServerError() {
        Exception exception = new Exception("Unexpected error");

        ResponseEntity<ProblemDetail> response = handler.handleGlobalException(exception);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().getDetail()).isEqualTo("Internal server error");
    }
}