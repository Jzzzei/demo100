package com.ecommerce.exception;

import org.springframework.http.HttpStatus;

public class BusinessException extends EcommerceException {
    public BusinessException(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
} 