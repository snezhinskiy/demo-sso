package com.demosso.resourceserver.configuration;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

import java.util.Collection;
import java.util.Map;

public class CustomOAuth2AuthenticatedPrincipal implements OAuth2AuthenticatedPrincipal {

    private String username;
    private Collection<? extends GrantedAuthority> authorities;
    private Map<String, Object> attributes;

    public CustomOAuth2AuthenticatedPrincipal(String username, Collection<? extends GrantedAuthority> authorities, Map<String, Object> attributes) {
        this.username = username;
        this.authorities = authorities;
        this.attributes = attributes;
    }

    @Override
    public String getName() {
        return username;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }
}
