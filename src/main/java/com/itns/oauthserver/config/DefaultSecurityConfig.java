package com.itns.oauthserver.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import com.itns.oauthserver.service.CustomAuthenticationProvider;

/**
 * It's a class that extends WebSecurityConfigurerAdapter and overrides the configure(HttpSecurity
 * http) method.
 */
@EnableWebSecurity
public class DefaultSecurityConfig {

    @Autowired
    private CustomAuthenticationProvider customAuthenticationProvider;

    /**
     * This function is called by Spring Security to create a default security filter chain. The
     * default security filter chain is used when no other security filter chain matches the request.
     * The default security filter chain is configured to require authentication for all requests.
     * 
     * @param http The HttpSecurity object that is used to build the SecurityFilterChain.
     * @return A SecurityFilterChain
     */
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(authorizeRequests ->
                        authorizeRequests.anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults());
        return http.build();
    }

    /**
     * This function is called by Spring Security to bind the custom authentication provider to the
     * authentication manager.
     * 
     * @param authenticationManagerBuilder This is the AuthenticationManagerBuilder object that is used
     * to create the AuthenticationManager.
     */
    @Autowired
    public void bindAuthenticationProvider(AuthenticationManagerBuilder authenticationManagerBuilder) {
        authenticationManagerBuilder
                .authenticationProvider(customAuthenticationProvider);
    }
}
