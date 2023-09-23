package com.demosso.authorizationserver.configuration;

import com.demosso.authorizationserver.security.socialLogin.SocialLoginAuthenticationSuccessHandler;
import com.demosso.authorizationserver.security.socialLogin.UserServiceOAuth2UserHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
        AuthenticationSuccessHandler authenticationSuccessHandler
    ) throws Exception {
        return http
            .authorizeHttpRequests(
                authorize -> authorize
                    .anyRequest().authenticated()
            )
            .formLogin(withDefaults())
            .oauth2Login(oauth ->
                oauth
                    .successHandler(authenticationSuccessHandler)
            )
            .logout((logout) -> logout.permitAll())
            .build();
    }

    @Bean
    public AuthenticationSuccessHandler authenticationSuccessHandler(UserServiceOAuth2UserHandler handler) {
        SocialLoginAuthenticationSuccessHandler authenticationSuccessHandler =
            new SocialLoginAuthenticationSuccessHandler();
        authenticationSuccessHandler.setOidcUserHandler(handler);
        return authenticationSuccessHandler;
    }
}
