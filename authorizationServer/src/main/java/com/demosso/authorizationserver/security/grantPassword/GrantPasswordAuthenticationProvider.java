package com.demosso.authorizationserver.security.grantPassword;

import com.demosso.authorizationserver.security.CustomUserDetails;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;

import java.security.Principal;

import static com.demosso.authorizationserver.security.grantPassword.AuthorizationGrantTypePassword.GRANT_PASSWORD;


public class GrantPasswordAuthenticationProvider implements AuthenticationProvider {

    private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    private final Log logger = LogFactory.getLog(getClass());
    private final OAuth2AuthorizationService authorizationService;
    private final UserDetailsService userDetailsService;
    private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;
    private final PasswordEncoder passwordEncoder;

    public GrantPasswordAuthenticationProvider(
        OAuth2AuthorizationService authorizationService,
        OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator,
        UserDetailsService userDetailsService,
        PasswordEncoder passwordEncoder
    ) {
        Assert.notNull(authorizationService, "authorizationService cannot be null");
        Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
        Assert.notNull(userDetailsService, "userDetailsService cannot be null");
        this.authorizationService = authorizationService;
        this.tokenGenerator = tokenGenerator;
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        GrantPasswordAuthenticationToken customPasswordAuthenticationToken =
            (GrantPasswordAuthenticationToken) authentication;

        // Ensure the client is authenticated
        OAuth2ClientAuthenticationToken clientPrincipal =
            getAuthenticatedClientElseThrowInvalidClient(customPasswordAuthenticationToken);

        RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Retrieved registered client");
        }

        // Ensure the client is configured to use this authorization grant type
        if (registeredClient == null || !registeredClient.getAuthorizationGrantTypes().contains(GRANT_PASSWORD)) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Retrieved authorization with username and password");
        }

        String username = customPasswordAuthenticationToken.getUsername();
        String password = customPasswordAuthenticationToken.getPassword();

        UserDetails user = null;
        try {
            user = userDetailsService.loadUserByUsername(username);
        } catch (UsernameNotFoundException e) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
        }

        if (!user.getUsername().equals(username)
            || !passwordEncoder.matches(password, user.getPassword())
        ) {
            throw new OAuth2AuthenticationException(OAuth2ErrorCodes.ACCESS_DENIED);
        }

        ((OAuth2ClientAuthenticationToken) SecurityContextHolder.getContext().getAuthentication())
            .setDetails(
                new CustomUserDetails(username, user.getAuthorities())
            );

        DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
            .registeredClient(registeredClient)
            .principal(clientPrincipal)
            .authorizationServerContext(
                // Issuer contains here
                AuthorizationServerContextHolder.getContext()
            )
            .authorizedScopes(registeredClient.getScopes())
            .authorizationGrantType(GRANT_PASSWORD)
            .authorizationGrant(customPasswordAuthenticationToken);

        // Generate the access token
        OAuth2TokenContext tokenContext = tokenContextBuilder
            .tokenType(OAuth2TokenType.ACCESS_TOKEN)
            .build();

        OAuth2Token generatedAccessToken = this.tokenGenerator.generate(tokenContext);

        if (generatedAccessToken == null) {
            OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                "The token generator failed to generate the access token.", ERROR_URI);
            throw new OAuth2AuthenticationException(error);
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Generated access token");
        }

        // ----- Access token -----
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
            OAuth2AccessToken.TokenType.BEARER,
            generatedAccessToken.getTokenValue(),
            generatedAccessToken.getIssuedAt(),
            generatedAccessToken.getExpiresAt(),
            tokenContext.getAuthorizedScopes()
        );

        // Initialize the OAuth2Authorization
        OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(registeredClient)
            .attribute(Principal.class.getName(), clientPrincipal)
            .principalName(clientPrincipal.getName())
            .authorizationGrantType(GRANT_PASSWORD)
            .authorizedScopes(registeredClient.getScopes());

        if (generatedAccessToken instanceof ClaimAccessor) {
            authorizationBuilder.token(accessToken, (metadata) ->
                metadata.put(
                    OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
                    ((ClaimAccessor) generatedAccessToken).getClaims()
                )
            );
        } else {
            authorizationBuilder.accessToken(accessToken);
        }

        // ----- Refresh token -----
        OAuth2RefreshToken refreshToken = null;

        if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)
            && !clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)
        ) {
            tokenContext = tokenContextBuilder
                .tokenType(OAuth2TokenType.REFRESH_TOKEN)
                .build();

            OAuth2Token generatedRefreshToken = this.tokenGenerator.generate(tokenContext);

            if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
                OAuth2Error error = new OAuth2Error(OAuth2ErrorCodes.SERVER_ERROR,
                    "The token generator failed to generate the refresh token.", ERROR_URI);
                throw new OAuth2AuthenticationException(error);
            }

            refreshToken = (OAuth2RefreshToken) generatedRefreshToken;
            authorizationBuilder.refreshToken(refreshToken);
        }

        OAuth2Authorization authorization = authorizationBuilder.build();

        this.authorizationService.save(authorization);

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Saved authorization");
        }

        if (this.logger.isTraceEnabled()) {
            this.logger.trace("Authenticated token request");
        }

        return new OAuth2AccessTokenAuthenticationToken(
            registeredClient, clientPrincipal, accessToken, refreshToken
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return GrantPasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }

    private static OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(Authentication authentication) {
        OAuth2ClientAuthenticationToken clientPrincipal = null;

        if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
            clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
        }

        if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
            return clientPrincipal;
        }

        throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
    }
}
