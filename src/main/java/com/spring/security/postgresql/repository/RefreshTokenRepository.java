package com.spring.security.postgresql.repository;

import java.util.Optional;

import com.spring.security.postgresql.models.RefreshToken;
import com.spring.security.postgresql.models.User;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    @Override
    Optional<RefreshToken> findById(Long id);

    Optional<RefreshToken> findByToken(String token);

    @Modifying
    int deleteByUser(User user);

}