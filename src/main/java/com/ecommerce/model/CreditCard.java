package com.ecommerce.model;

import jakarta.persistence.*;
import lombok.Data;

@Data
@Entity
@Table(name = "credit_cards")
public class CreditCard {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;
    
    @Column(nullable = false)
    private String cardNumber;
    
    @Column(nullable = false)
    private String cardHolderName;
    
    @Column(nullable = false)
    private Integer expirationMonth;
    
    @Column(nullable = false)
    private Integer expirationYear;
    
    @Column(nullable = false)
    private String cvv;
    
    private boolean isDefault;
} 