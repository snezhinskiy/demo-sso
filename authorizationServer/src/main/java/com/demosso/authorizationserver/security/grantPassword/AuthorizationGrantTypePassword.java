package com.demosso.authorizationserver.security.grantPassword;

import org.springframework.security.oauth2.core.AuthorizationGrantType;

public class AuthorizationGrantTypePassword {
    public static final AuthorizationGrantType GRANT_PASSWORD =
        new AuthorizationGrantType("grant_password");
}
