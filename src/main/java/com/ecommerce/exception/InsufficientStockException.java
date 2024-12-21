package com.ecommerce.exception;

import org.springframework.http.HttpStatus;

public class InsufficientStockException extends EcommerceException {
    public InsufficientStockException(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
} 