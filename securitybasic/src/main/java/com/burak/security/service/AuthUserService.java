package com.burak.security.service;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.burak.security.dto.LoginRequest;
import com.burak.security.dto.RegisterRequest;
import com.burak.security.entity.AuthRole;
import com.burak.security.entity.AuthUser;
import com.burak.security.repository.AuthUserRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthUserService {

	private final AuthUserRepository userRepository;
	private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

	public ResponseEntity<String> registerUser(RegisterRequest registerRequest) {
		if (userRepository.findByUsername(registerRequest.getUsername()) != null) {
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("User already exist.");
		}
		AuthUser user = new AuthUser();
		user.setUsername(registerRequest.getUsername());
		user.setPassword(passwordEncoder.encode(registerRequest.getPassword()));
		user.setRole(AuthRole.USER);
		return ResponseEntity.status(HttpStatus.CREATED).body("Register successful.");
	}
	
	public ResponseEntity<String> loginUser(LoginRequest loginRequest) {
	    try {
	        Authentication authentication = authenticationManager.authenticate(
	                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
	        );
	        
	        SecurityContextHolder.getContext().setAuthentication(authentication);

	        return ResponseEntity.status(HttpStatus.OK).body("Login success.");
	    } catch (AuthenticationException ex) {
	        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Wrong username or password.");
	    }
	}
}
