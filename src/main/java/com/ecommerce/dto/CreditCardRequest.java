package com.ecommerce.dto;

import jakarta.validation.constraints.*;
import lombok.Data;

@Data
public class CreditCardRequest {
    @NotBlank(message = "Card number is required")
    @Pattern(regexp = "\\d{16}", message = "Card number must be 16 digits")
    private String cardNumber;
    
    @NotBlank(message = "Card holder name is required")
    private String cardHolderName;
    
    @NotNull(message = "Expiration month is required")
    @Min(value = 1, message = "Invalid expiration month")
    @Max(value = 12, message = "Invalid expiration month")
    private Integer expirationMonth;
    
    @NotNull(message = "Expiration year is required")
    @Min(value = 2023, message = "Card has expired")
    private Integer expirationYear;
    
    @NotBlank(message = "CVV is required")
    @Pattern(regexp = "\\d{3,4}", message = "CVV must be 3 or 4 digits")
    private String cvv;
    
    private boolean isDefault;
} 