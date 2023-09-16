package com.demosso.authorizationserver.service;


import com.demosso.authorizationserver.domain.User;

public interface UserService {
	User getByUsername(String username);

    User save(User user);
}