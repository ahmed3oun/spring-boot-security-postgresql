package com.spring.security.postgresql.payload.request;

import javax.validation.constraints.Email;

public class ForgotPasswordRequest {

    @Email
    private String email;

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

}