package com.demosso.resourceserver.configuration;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.util.StringUtils;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class CustomOpaqueTokenAuthenticationConverter implements OpaqueTokenAuthenticationConverter {

    @Override
    public Authentication convert(String introspectedToken, OAuth2AuthenticatedPrincipal authenticatedPrincipal) {
        Map<String, Object> attributes = authenticatedPrincipal.getAttributes();

        // authorities (OPTIONAL)
        Collection<? extends GrantedAuthority> authorities = AuthorityUtils.NO_AUTHORITIES;
        if (authenticatedPrincipal.getAttributes().containsKey("authorities")) {
            authorities =
                ((List<String>)authenticatedPrincipal.getAttributes().get("authorities")).stream()
                    .map(auth -> new SimpleGrantedAuthority(auth))
                    .collect(Collectors.toUnmodifiableSet());
        }

        // username (OPTIONAL)
        String username = null;
        if (attributes.containsKey("username")
            && StringUtils.hasText((String) attributes.get("username"))
        ) {
            username = (String) attributes.get("username");
        }

        OAuth2AccessToken accessToken = new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            introspectedToken,
            authenticatedPrincipal.getAttribute(IdTokenClaimNames.IAT),
            authenticatedPrincipal.getAttribute(IdTokenClaimNames.EXP)
        );

        CustomOAuth2AuthenticatedPrincipal customOAuth2User = new CustomOAuth2AuthenticatedPrincipal(username, authorities, attributes);

        return new BearerTokenAuthentication(
            customOAuth2User,
            accessToken,
            customOAuth2User.getAuthorities()
        );
    }
}
