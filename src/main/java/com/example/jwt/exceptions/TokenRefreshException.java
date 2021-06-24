package com.example.jwt.exceptions;


import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus
public class TokenRefreshException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public TokenRefreshException(String token, String message) {
        super(String.format("Failed for [%s]: %s", token, message));
    }
}
