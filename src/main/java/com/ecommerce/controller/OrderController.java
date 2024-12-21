package com.ecommerce.controller;

import com.ecommerce.dto.OrderRequest;
import com.ecommerce.model.Order;
import com.ecommerce.service.OrderService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/orders")
@Tag(name = "Order", description = "Order management APIs")
@SecurityRequirement(name = "bearerAuth")
public class OrderController {
    @Autowired
    private OrderService orderService;
    
    @Operation(summary = "Create a new order")
    @PostMapping
    public ResponseEntity<Order> createOrder(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody OrderRequest orderRequest) {
        return ResponseEntity.ok(orderService.createOrder(
            userDetails.getUsername(), 
            orderRequest.getShippingAddress(), 
            orderRequest.getPaymentMethod()));
    }
    
    @Operation(summary = "Get user's orders")
    @GetMapping
    public ResponseEntity<List<Order>> getUserOrders(
            @AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(orderService.getUserOrders(userDetails.getUsername()));
    }
    
    @Operation(summary = "Get order by ID")
    @GetMapping("/{orderId}")
    public ResponseEntity<Order> getOrder(
            @Parameter(description = "Order ID") @PathVariable Long orderId) {
        return ResponseEntity.ok(orderService.getOrder(orderId));
    }
    
    @Operation(summary = "Confirm order")
    @PostMapping("/{orderId}/confirm")
    public ResponseEntity<Order> confirmOrder(
            @AuthenticationPrincipal UserDetails userDetails,
            @Parameter(description = "Order ID") @PathVariable Long orderId) {
        return ResponseEntity.ok(orderService.confirmOrder(userDetails.getUsername(), orderId));
    }
    
    @Operation(summary = "Cancel order")
    @PostMapping("/{orderId}/cancel")
    public ResponseEntity<Order> cancelOrder(
            @AuthenticationPrincipal UserDetails userDetails,
            @Parameter(description = "Order ID") @PathVariable Long orderId) {
        return ResponseEntity.ok(orderService.cancelOrder(userDetails.getUsername(), orderId));
    }
    
    @Operation(summary = "Get order summary")
    @GetMapping("/{orderId}/summary")
    public ResponseEntity<Map<String, Object>> getOrderSummary(
            @Parameter(description = "Order ID") @PathVariable Long orderId) {
        return ResponseEntity.ok(orderService.getOrderSummary(orderId));
    }
} 