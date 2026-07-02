package com.innowise.authservice.model.entity;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class RefreshTokenTest {

    private static final LocalDateTime FIXED_DATE = LocalDateTime.of(2026, 5, 19, 3, 1);

    @Test
    void testEqualsAndHashCode() {
        RefreshToken first = new RefreshToken();
        first.setToken("token1");

        RefreshToken second = new RefreshToken();
        second.setToken("token1");

        RefreshToken third = new RefreshToken();
        third.setToken("token2");

        assertThat(first).isEqualTo(first);
        assertThat(first).isEqualTo(second);
        assertThat(second).isEqualTo(first);

        RefreshToken fourth = new RefreshToken();
        fourth.setToken("token1");

        assertThat(first).isEqualTo(second);
        assertThat(second).isEqualTo(fourth);
        assertThat(first).isEqualTo(fourth);
        assertThat(first).isNotEqualTo(null);
        assertThat(first).isNotEqualTo(new Object());
        assertThat(first).isNotEqualTo(third);
        assertThat(third).isNotEqualTo(first);
        assertThat(first.hashCode()).isEqualTo(second.hashCode());
        assertThat(first.hashCode()).isNotEqualTo(third.hashCode());

        Set<RefreshToken> set = new HashSet<>();
        set.add(first);
        assertThat(set).contains(second);
        assertThat(set).doesNotContain(third);
    }

    @Test
    void testEqualsWithNullToken() {
        RefreshToken first = new RefreshToken();
        first.setToken(null);

        RefreshToken second = new RefreshToken();
        second.setToken(null);

        RefreshToken third = new RefreshToken();
        third.setToken("token");

        assertThat(first).isNotEqualTo(second);
        assertThat(first).isNotEqualTo(third);
    }

    @Test
    void testEqualsWithMixedNullToken() {
        RefreshToken token = new RefreshToken();
        token.setToken("token");

        RefreshToken tokenWithNull = new RefreshToken();
        tokenWithNull.setToken(null);

        assertThat(token).isNotEqualTo(tokenWithNull);
        assertThat(tokenWithNull).isNotEqualTo(token);
    }

    @Test
    void testEqualsShouldIgnoreNonBusinessFields() {
        RefreshToken rt1 = new RefreshToken();
        rt1.setToken("token1");
        rt1.setId(1L);
        rt1.setExpiryDate(FIXED_DATE);
        rt1.setRevoked(false);
        rt1.setCreatedAt(FIXED_DATE);

        UserCredential user = new UserCredential();
        rt1.setUserCredential(user);

        RefreshToken rt2 = new RefreshToken();
        rt2.setToken("token1");
        rt2.setId(2L);
        rt2.setExpiryDate(FIXED_DATE.plusDays(1));
        rt2.setRevoked(true);
        rt2.setCreatedAt(FIXED_DATE.minusDays(1));
        rt2.setUserCredential(null);

        assertThat(rt1).isEqualTo(rt2);
        assertThat(rt1.hashCode()).isEqualTo(rt2.hashCode());
    }

    @Test
    void testHashCodeStability() {
        RefreshToken token = new RefreshToken();
        token.setToken("token");

        int first = token.hashCode();
        int second = token.hashCode();
        assertThat(first).isEqualTo(second);
    }

    @Test
    void testSetContainsAfterChangingNonBusinessFields() {
        RefreshToken oldToken = new RefreshToken();
        oldToken.setToken("token");
        oldToken.setRevoked(false);

        RefreshToken newToken = new RefreshToken();
        newToken.setToken("token");
        newToken.setRevoked(true);

        Set<RefreshToken> set = new HashSet<>();
        set.add(oldToken);
        assertThat(set).contains(newToken);
    }

    @Test
    void testDefaultConstructor() {
        RefreshToken token = new RefreshToken();

        assertThat(token.getToken()).isNull();
        assertThat(token.isRevoked()).isFalse();
        assertThat(token.getId()).isNull();
        assertThat(token.getExpiryDate()).isNull();
        assertThat(token.getUserCredential()).isNull();
        assertThat(token.getCreatedAt()).isNull();
    }

    @Test
    void testSettersAndGetters() {
        RefreshToken token = new RefreshToken();
        token.setId(1L);
        token.setToken("test-token");
        token.setExpiryDate(FIXED_DATE);
        token.setRevoked(true);

        UserCredential user = new UserCredential();
        token.setUserCredential(user);
        token.setCreatedAt(FIXED_DATE);

        assertThat(token.getId()).isEqualTo(1L);
        assertThat(token.getToken()).isEqualTo("test-token");
        assertThat(token.getExpiryDate()).isEqualTo(FIXED_DATE);
        assertThat(token.isRevoked()).isTrue();
        assertThat(token.getUserCredential()).isEqualTo(user);
        assertThat(token.getCreatedAt()).isEqualTo(FIXED_DATE);
    }
}