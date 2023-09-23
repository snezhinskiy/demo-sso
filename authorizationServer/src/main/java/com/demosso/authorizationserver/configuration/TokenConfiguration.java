package com.demosso.authorizationserver.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.util.StringUtils;

import java.util.stream.Collectors;

@Configuration(proxyBeanMethods = false)
public class TokenConfiguration {

    @Bean
    public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(
        OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer
    ) {
        OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
        accessTokenGenerator.setAccessTokenCustomizer(accessTokenCustomizer);
        OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();

        return new DelegatingOAuth2TokenGenerator(
            accessTokenGenerator, refreshTokenGenerator
        );
    }

    @Bean
    public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer () {
        return context -> {
            UserDetails userDetails = null;

            if (context.getPrincipal() instanceof OAuth2ClientAuthenticationToken) {
                userDetails = (UserDetails) context.getPrincipal().getDetails();
            } else if (context.getPrincipal() instanceof AbstractAuthenticationToken) {
                userDetails = (UserDetails) context.getPrincipal().getPrincipal();
            } else {
                throw new IllegalStateException("Unexpected token type");
            }

            if (!StringUtils.hasText(userDetails.getUsername())) {
                throw new IllegalStateException("Bad UserDetails, username is empty");
            }

            context.getClaims()
                .claim(
                    "authorities",
                    userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toSet())
                )
                .claim(
                    "username", userDetails.getUsername()
                );
        };
    }
}
