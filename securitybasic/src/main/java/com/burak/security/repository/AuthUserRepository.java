package com.burak.security.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.burak.security.entity.AuthUser;

public interface AuthUserRepository extends JpaRepository<AuthUser, Long> {
    AuthUser findByUsername(String username);
}
