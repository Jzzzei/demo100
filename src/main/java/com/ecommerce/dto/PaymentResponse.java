package com.ecommerce.dto;

import com.ecommerce.model.PaymentStatus;
import lombok.Data;
import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
public class PaymentResponse {
    private PaymentStatus status;
    private String transactionId;
    private BigDecimal amount;
    private LocalDateTime paymentDate;
    private String error;
} 