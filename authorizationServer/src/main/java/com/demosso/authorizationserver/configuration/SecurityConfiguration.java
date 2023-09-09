package com.demosso.authorizationserver.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        return http
            .authorizeHttpRequests(
                authorize -> authorize
                    .anyRequest().authenticated()
            )
            .formLogin(withDefaults())
            .logout((logout) -> logout.permitAll())
            .build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
            .username("admin")

            // {noop} means "no operation," i.e., a raw password without any encoding applied.
            .password("{noop}secret")

            .roles("USER")
            .authorities("ARTICLE_READ", "ARTICLE_WRITE")
            .build();

        return new InMemoryUserDetailsManager(user);
    }
}
