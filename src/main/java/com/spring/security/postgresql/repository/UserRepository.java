package com.spring.security.postgresql.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.spring.security.postgresql.models.User;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
  Optional<User> findByUsername(String username);

  Optional<User> findByEmail(String username);

  Optional<User> findByResetPasswordToken(String token);

  Boolean existsByUsername(String username);

  Boolean existsByEmail(String email);
}
