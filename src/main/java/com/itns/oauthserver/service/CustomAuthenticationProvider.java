package com.itns.oauthserver.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * This class is a custom authentication provider that implements the Spring Security
 * AuthenticationProvider interface.
 */
@Service
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * If the user is not found, throw an exception. If the user is found, check the password. If the
     * password is correct, return the user. If the password is incorrect, throw an exception.
     * 
     * @param authentication This is the object that contains the username and password that the user
     * entered.
     * @return A new Authentication object.
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = authentication.getCredentials().toString();
        UserDetails user= customUserDetailsService.loadUserByUsername(username);
        return checkPassword(user,password);
    }

    /**
     * If the password matches, return a new UsernamePasswordAuthenticationToken with the user's
     * username, password, and authorities
     * 
     * @param user The user object that was returned by the loadUserByUsername method.
     * @param rawPassword The password that the user entered
     * @return A new UsernamePasswordAuthenticationToken object.
     */
    private Authentication checkPassword(UserDetails user, String rawPassword) {
        if(passwordEncoder.matches(rawPassword, user.getPassword())) {
            return new UsernamePasswordAuthenticationToken(user.getUsername(),
                    user.getPassword(),
                    user.getAuthorities());
        }
        else {
            throw new BadCredentialsException("Bad Credentials");
        }
    }

    /**
     * If the authentication object is an instance of UsernamePasswordAuthenticationToken, then return
     * true, otherwise return false.
     * 
     * @param authentication The authentication object that is being authenticated.
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
