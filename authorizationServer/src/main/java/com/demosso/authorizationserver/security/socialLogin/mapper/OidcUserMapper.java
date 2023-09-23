package com.demosso.authorizationserver.security.socialLogin.mapper;

import com.demosso.authorizationserver.domain.User;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

public interface OidcUserMapper {
    OidcUser map(OidcUser oidcUser);
    OidcUser map(OidcIdToken idToken, OidcUserInfo userInfo, User user);
}
