package com.burak.security.service;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.burak.security.entity.AuthRole;
import com.burak.security.entity.AuthUser;
import com.burak.security.repository.AuthUserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthUserService {

	private final AuthUserRepository userRepository;
	private final PasswordEncoder passwordEncoder;

	public AuthUser registerUser(String username, String password) {
		if (userRepository.findByUsername(username) != null) {
			throw new RuntimeException("Kullanıcı zaten mevcut");
		}
		AuthUser user = new AuthUser();
		user.setUsername(username);
		user.setPassword(passwordEncoder.encode(password));
		user.setRole(AuthRole.USER);
		return userRepository.save(user);
	}

	public AuthUser findByUsername(String username) {
		return userRepository.findByUsername(username);
	}
}
