package com.ecommerce.controller;

import com.ecommerce.dto.PaymentResponse;
import com.ecommerce.model.Payment;
import com.ecommerce.model.PaymentStatus;
import com.ecommerce.service.PaymentService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/payments")
@Tag(name = "Payment", description = "Payment management APIs")
@SecurityRequirement(name = "bearerAuth")
public class PaymentController {
    @Autowired
    private PaymentService paymentService;
    
    @Operation(summary = "Process payment for order")
    @PostMapping("/process")
    public ResponseEntity<?> processPayment(
            @Parameter(description = "Order ID") @RequestParam Long orderId,
            @Parameter(description = "Payment method") @RequestParam String paymentMethod) {
        try {
            PaymentResponse response = paymentService.processPayment(orderId, paymentMethod);
            if (response.getStatus() == PaymentStatus.FAILED) {
                return ResponseEntity.badRequest().body(response);
            }
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }
    
    @Operation(summary = "Retry failed payment")
    @PostMapping("/retry")
    public ResponseEntity<?> retryPayment(
            @Parameter(description = "Order ID") @RequestParam Long orderId,
            @Parameter(description = "Payment method") @RequestParam String paymentMethod) {
        try {
            PaymentResponse response = paymentService.retryPayment(orderId, paymentMethod);
            if (response.getStatus() == PaymentStatus.FAILED) {
                return ResponseEntity.badRequest().body(response);
            }
            return ResponseEntity.ok(response);
        } catch (RuntimeException e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }
    
    @Operation(summary = "Get payment details by ID")
    @GetMapping("/{paymentId}")
    public ResponseEntity<Payment> getPayment(
            @Parameter(description = "Payment ID") @PathVariable Long paymentId) {
        return ResponseEntity.ok(paymentService.getPayment(paymentId));
    }
    
    @Operation(summary = "Get payment details by order ID")
    @GetMapping("/order/{orderId}")
    public ResponseEntity<Payment> getPaymentByOrder(
            @Parameter(description = "Order ID") @PathVariable Long orderId) {
        return ResponseEntity.ok(paymentService.getPaymentByOrder(orderId));
    }
} 