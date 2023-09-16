package com.demosso.authorizationserver.service.impl;

import com.demosso.authorizationserver.domain.User;
import com.demosso.authorizationserver.repository.UserRepository;
import com.demosso.authorizationserver.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;


@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {
	private final UserRepository repository;

	@Override
	public User getByUsername(String username) {
		if (!StringUtils.hasText(username)) {
			return null;
		}

		return repository.findByUsername(username).orElse(null);
	}

	@Override
	public User save(User entity) {
		return repository.save(entity);
	}
}
