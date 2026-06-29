package com.innowise.authservice.controller;

import com.innowise.authservice.security.JwtUtil;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@RestController
public class JwksController {

    private final JwtUtil jwtUtil;

    public JwksController(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @GetMapping("/oauth2/jwks")
    public Map<String, Object> getJwks() {
        RSAPublicKey rsaPublicKey = jwtUtil.getRsaPublicKey();
        Map<String, Object> jsonWebKey = new HashMap<>();
        jsonWebKey.put("kty", "RSA");
        jsonWebKey.put("alg", "RS256");
        jsonWebKey.put("use", "sig");
        jsonWebKey.put("kid", "auth-service-key-id");
        jsonWebKey.put("n", Base64.getUrlEncoder().withoutPadding().encodeToString(rsaPublicKey.getModulus().toByteArray()));
        jsonWebKey.put("e", Base64.getUrlEncoder().withoutPadding().encodeToString(rsaPublicKey.getPublicExponent().toByteArray()));

        return Collections.singletonMap("keys", Collections.singletonList(jsonWebKey));
    }
}