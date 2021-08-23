package com.spring.security.postgresql.security.services;

import com.spring.security.postgresql.models.User;
import com.spring.security.postgresql.repository.UserRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class ForgotPasswordService {
    @Autowired
    private UserRepository userRepo;

    public void updateResetPasswordToken(String token, String email) {
        User user = userRepo.findByEmail(email).get();
        if (user != null) {
            user.setResetPasswordToken(token);
            userRepo.save(user);
        } else {
            throw new RuntimeException("Could not find any user with the email " + email);

        }
    }

    public User getByResetPasswordToken(String token) {
        return userRepo.findByResetPasswordToken(token).get();
    }

    public void updatePassword(User user, String newPassword) {
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String encodedPassword = passwordEncoder.encode(newPassword);
        user.setPassword(encodedPassword);

        user.setResetPasswordToken(null);
        userRepo.save(user);
    }
}