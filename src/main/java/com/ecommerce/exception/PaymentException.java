package com.ecommerce.exception;

import org.springframework.http.HttpStatus;

public class PaymentException extends EcommerceException {
    public PaymentException(String message) {
        super(message, HttpStatus.BAD_REQUEST);
    }
} 