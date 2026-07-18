package com.innowise.authservice.model.entity;

import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class UserCredentialTest {

    private static final LocalDateTime FIXED_DATE = LocalDateTime.of(2026, 5, 19, 3, 1);

    @Test
    void testEqualsAndHashCode() {
        UserCredential first = new UserCredential();
        first.setUsername("Bob");

        UserCredential second = new UserCredential();
        second.setUsername("Bob");

        UserCredential third = new UserCredential();
        third.setUsername("Sam");

        assertThat(first).isEqualTo(first);
        assertThat(first).isEqualTo(second);
        assertThat(second).isEqualTo(first);

        UserCredential fourth = new UserCredential();
        fourth.setUsername("Bob");

        assertThat(first).isEqualTo(second);
        assertThat(second).isEqualTo(fourth);
        assertThat(first).isEqualTo(fourth);
        assertThat(first).isNotEqualTo(null);
        assertThat(first).isNotEqualTo(new Object());
        assertThat(first).isNotEqualTo(third);
        assertThat(third).isNotEqualTo(first);
        assertThat(first.hashCode()).isEqualTo(second.hashCode());
        assertThat(first.hashCode()).isNotEqualTo(third.hashCode());

        Set<UserCredential> set = new HashSet<>();
        set.add(first);
        assertThat(set).contains(second);
        assertThat(set).doesNotContain(third);
    }

    @Test
    void testEqualsWithNullUsername() {
        UserCredential first = new UserCredential();
        first.setUsername(null);

        UserCredential second = new UserCredential();
        second.setUsername(null);

        UserCredential third = new UserCredential();
        third.setUsername("Bob");

        assertThat(first).isNotEqualTo(second);
        assertThat(first).isNotEqualTo(third);
    }

    @Test
    void testEqualsWithMixedNullUsername() {
        UserCredential user = new UserCredential();
        user.setUsername("Bob");

        UserCredential userWithNull = new UserCredential();
        userWithNull.setUsername(null);

        assertThat(user).isNotEqualTo(userWithNull);
        assertThat(userWithNull).isNotEqualTo(user);
    }

    @Test
    void testEqualsShouldIgnoreNonBusinessFields() {
        UserCredential user = new UserCredential();
        user.setUsername("Bob");
        user.setId(1L);
        user.setRole("USER");
        user.setPasswordHash("hash1");
        user.setActive(true);
        user.setUserServiceId(100L);
        user.setCreatedAt(FIXED_DATE);
        user.setUpdatedAt(FIXED_DATE);

        UserCredential another = new UserCredential();
        another.setUsername("Bob");
        another.setId(2L);
        another.setRole("ADMIN");
        another.setPasswordHash("hash2");
        another.setActive(false);
        another.setUserServiceId(200L);
        another.setCreatedAt(FIXED_DATE);
        another.setUpdatedAt(FIXED_DATE);

        assertThat(user).isEqualTo(another);
        assertThat(user.hashCode()).isEqualTo(another.hashCode());
    }

    @Test
    void testHashCodeStability() {
        UserCredential user = new UserCredential();
        user.setUsername("Bob");

        int first = user.hashCode();
        int second = user.hashCode();
        assertThat(first).isEqualTo(second);
    }

    @Test
    void testSetContainsAfterChangingNonBusinessFields() {
        UserCredential oldUser = new UserCredential();
        oldUser.setUsername("Bob");
        oldUser.setRole("USER");

        UserCredential newUser = new UserCredential();
        newUser.setUsername("Bob");
        newUser.setRole("ADMIN");

        Set<UserCredential> set = new HashSet<>();
        set.add(oldUser);
        assertThat(set).contains(newUser);
    }

    @Test
    void testAllArgsConstructorAndGetters() {
        UserCredential user = new UserCredential(1L, "Bob", "USER", "hash", true,
                100L, FIXED_DATE, FIXED_DATE, null
        );

        assertThat(user.getId()).isEqualTo(1L);
        assertThat(user.getUsername()).isEqualTo("Bob");
        assertThat(user.getRole()).isEqualTo("USER");
        assertThat(user.getPasswordHash()).isEqualTo("hash");
        assertThat(user.isActive()).isTrue();
        assertThat(user.getUserServiceId()).isEqualTo(100L);
        assertThat(user.getCreatedAt()).isEqualTo(FIXED_DATE);
        assertThat(user.getUpdatedAt()).isEqualTo(FIXED_DATE);
        assertThat(user.getRefreshTokens()).isNull();
    }

    @Test
    void testNoArgsConstructorAndSetters() {
        UserCredential user = new UserCredential();
        user.setId(2L);
        user.setUsername("Bob");
        user.setRole("ADMIN");
        user.setPasswordHash("secret");
        user.setActive(false);
        user.setUserServiceId(200L);
        user.setCreatedAt(FIXED_DATE);
        user.setUpdatedAt(FIXED_DATE);
        user.setRefreshTokens(new ArrayList<>());

        assertThat(user.getId()).isEqualTo(2L);
        assertThat(user.getUsername()).isEqualTo("Bob");
        assertThat(user.getRole()).isEqualTo("ADMIN");
        assertThat(user.getPasswordHash()).isEqualTo("secret");
        assertThat(user.isActive()).isFalse();
        assertThat(user.getUserServiceId()).isEqualTo(200L);
        assertThat(user.getCreatedAt()).isEqualTo(FIXED_DATE);
        assertThat(user.getUpdatedAt()).isEqualTo(FIXED_DATE);
        assertThat(user.getRefreshTokens()).isEmpty();
    }
}