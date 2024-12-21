package com.ecommerce.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class EcommerceException extends RuntimeException {
    private final HttpStatus status;
    
    public EcommerceException(String message, HttpStatus status) {
        super(message);
        this.status = status;
    }
} 