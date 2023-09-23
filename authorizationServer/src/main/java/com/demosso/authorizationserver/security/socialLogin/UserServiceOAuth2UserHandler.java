package com.demosso.authorizationserver.security.socialLogin;

import com.demosso.authorizationserver.domain.Role;
import com.demosso.authorizationserver.domain.User;
import com.demosso.authorizationserver.service.RoleService;
import com.demosso.authorizationserver.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;

import java.util.Collection;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class UserServiceOAuth2UserHandler implements Consumer<OidcUser> {
    private final UserService userService;
    private final RoleService roleService;

    @Override
    public void accept(OidcUser user) {
        // Capture user in a local data store on first authentication
        CustomOidcUser oidcUser = (CustomOidcUser)user;

        if (oidcUser.getId() == null
            && this.userService.getByUsername(user.getName()) == null
        ) {
            Collection<GrantedAuthority> grantedAuthorities = (Collection<GrantedAuthority>)oidcUser.getAuthorities();
            User localUser = oidcUser.toInstantUser();
            Role defaultRole = roleService.getDefaultRole();

            if (defaultRole != null) {
                localUser.setRoles(Set.of(defaultRole));
            }

            this.userService.save(localUser);

            if (!CollectionUtils.isEmpty(localUser.getRoles())) {
                Set<? extends GrantedAuthority> authorities = localUser.getRoles().stream()
                    .flatMap(role -> role.getAuthorities().stream()
                        .map(authority -> new SimpleGrantedAuthority(authority.getName()))
                    )
                    .collect(Collectors.toSet());

                grantedAuthorities.addAll(authorities);
            }

            oidcUser.setId(localUser.getId());
        }
    }
}