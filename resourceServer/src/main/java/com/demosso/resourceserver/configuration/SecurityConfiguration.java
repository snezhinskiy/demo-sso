package com.demosso.resourceserver.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http,
        OpaqueTokenAuthenticationConverter opaqueTokenAuthenticationConverter
    ) throws Exception {
        http.oauth2ResourceServer(
          auth -> auth
              .opaqueToken(
                  opaqueTokenConfigurer -> opaqueTokenConfigurer
                      .introspectionUri("http://localhost:8081/oauth2/introspect")
                      .introspectionClientCredentials("demo-client", "demo-secret")
                      .authenticationConverter(opaqueTokenAuthenticationConverter)
              )
        );

        http.authorizeHttpRequests(
            authorizationManagerRequestMatcherRegistry ->
                authorizationManagerRequestMatcherRegistry.anyRequest()
                    .authenticated()
        );

        return http.build();
    }

    @Bean
    public OpaqueTokenAuthenticationConverter opaqueTokenAuthenticationConverter() {
        return new CustomOpaqueTokenAuthenticationConverter();
    }
}
