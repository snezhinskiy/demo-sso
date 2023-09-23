package com.demosso.authorizationserver.service;


import com.demosso.authorizationserver.domain.Role;

public interface RoleService {
	Role getByName(String name);
	Role getDefaultRole();
}