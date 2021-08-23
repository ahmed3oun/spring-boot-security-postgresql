package com.spring.security.postgresql.payload.request;

import javax.validation.constraints.NotNull;

public class LogOutRequest {

    // @NotBlank
    @NotNull
    private Long userId;

    public Long getUserId() {
        return userId;
    }

}