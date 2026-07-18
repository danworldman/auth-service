package com.innowise.authservice.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {

    private final RSAPrivateKey rsaPrivateKey;
    @Getter
    private final RSAPublicKey rsaPublicKey;
    private final Long jwtAccessExpiration;
    private final Long jwtRefreshExpiration;

    public JwtUtil(
            @Value("${jwt.access-expiration}") Long jwtAccessExpiration,
            @Value("${jwt.refresh-expiration}") Long jwtRefreshExpiration) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        this.rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
        this.rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        this.jwtAccessExpiration = jwtAccessExpiration;
        this.jwtRefreshExpiration = jwtRefreshExpiration;
    }

    public String extractUsername(String jsonWebToken) {
        return extractClaim(jsonWebToken, Claims::getSubject);
    }

    public String extractRole(String jsonWebToken) {
        return extractClaim(jsonWebToken, claims -> claims.get("role", String.class));
    }

    public Date extractExpiration(String jsonWebToken) {
        return extractClaim(jsonWebToken, Claims::getExpiration);
    }

    public <T> T extractClaim(String jsonWebToken, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(jsonWebToken);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String jsonWebToken) {
        return Jwts.parser()
                .verifyWith(rsaPublicKey)
                .build()
                .parseSignedClaims(jsonWebToken)
                .getPayload();
    }

    private Boolean isTokenExpired(String jsonWebToken) {
        return extractExpiration(jsonWebToken).before(new Date());
    }

    public String generateAccessToken(UserDetails userDetails, Long userId, String securityRole) {
        Map<String, Object> tokenClaims = new HashMap<>();
        tokenClaims.put("role", securityRole);
        tokenClaims.put("user_id", userId);

        return createToken(tokenClaims, userDetails.getUsername(), jwtAccessExpiration);
    }

    private String createToken(Map<String, Object> tokenClaims, String tokenSubject, Long expirationTime) {
        return Jwts.builder()
                .claims(tokenClaims)
                .subject(tokenSubject)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expirationTime))
                .signWith(rsaPrivateKey, Jwts.SIG.RS256)
                .compact();
    }

    public Boolean validateToken(String jsonWebToken) {
        try {
            return !isTokenExpired(jsonWebToken);
        } catch (JwtException | IllegalArgumentException exception) {
            return false;
        }
    }

    public Long extractUserId(String jsonWebToken) {
        return extractClaim(jsonWebToken, claims -> claims.get("user_id", Long.class));
    }
}