package com.ecommerce.exception;

import org.springframework.http.HttpStatus;

public class UnauthorizedException extends EcommerceException {
    public UnauthorizedException(String message) {
        super(message, HttpStatus.UNAUTHORIZED);
    }
} 