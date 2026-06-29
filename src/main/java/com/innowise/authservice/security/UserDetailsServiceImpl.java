package com.innowise.authservice.security;

import com.innowise.authservice.dao.UserCredentialDAO;
import com.innowise.authservice.model.entity.UserCredential;
import java.util.Collections;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserCredentialDAO userCredentialDAO;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserCredential userCredential  = userCredentialDAO.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + username));

        return new User(
                userCredential .getUsername(),
                userCredential .getPasswordHash(),
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + userCredential .getRole()))
        );
    }
}