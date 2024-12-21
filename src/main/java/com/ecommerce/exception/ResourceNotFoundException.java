package com.ecommerce.exception;

import org.springframework.http.HttpStatus;

public class ResourceNotFoundException extends EcommerceException {
    public ResourceNotFoundException(String message) {
        super(message, HttpStatus.NOT_FOUND);
    }
} 