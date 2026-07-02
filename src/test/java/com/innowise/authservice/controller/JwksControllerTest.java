package com.innowise.authservice.controller;

import com.innowise.authservice.security.JwtUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwksControllerTest {

    @Mock
    private JwtUtil jwtUtil;

    @InjectMocks
    private JwksController jwksController;

    @Test
    void shouldReturnJwksWithValidStructure() {
        RSAPublicKey mockPublicKey = mock(RSAPublicKey.class);
        BigInteger modulus = new BigInteger("12345678901234567890");
        BigInteger exponent = BigInteger.valueOf(65537);

        when(mockPublicKey.getModulus()).thenReturn(modulus);
        when(mockPublicKey.getPublicExponent()).thenReturn(exponent);
        when(jwtUtil.getRsaPublicKey()).thenReturn(mockPublicKey);

        Map<String, Object> result = jwksController.getJwks();

        assertThat(result).containsKey("keys");
        assertThat(result.get("keys")).isInstanceOf(Iterable.class);

        Object keysObj = result.get("keys");
        assertThat(keysObj).asList().hasSize(1);

        Map<String, Object> key = (Map<String, Object>) ((Iterable<?>) keysObj).iterator().next();
        assertThat(key).containsEntry("kty", "RSA");
        assertThat(key).containsEntry("alg", "RS256");
        assertThat(key).containsEntry("use", "sig");
        assertThat(key).containsEntry("kid", "auth-service-key-id");
        assertThat(key).containsKey("n");
        assertThat(key).containsKey("e");

        String n = (String) key.get("n");
        String e = (String) key.get("e");
        assertThat(Base64.getUrlDecoder().decode(n)).isNotEmpty();
        assertThat(Base64.getUrlDecoder().decode(e)).isNotEmpty();
    }
}