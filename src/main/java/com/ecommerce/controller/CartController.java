package com.ecommerce.controller;

import com.ecommerce.dto.CartItemRequest;
import com.ecommerce.model.CartItem;
import com.ecommerce.service.CartService;
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

@RestController
@RequestMapping("/api/cart")
@Tag(name = "Cart", description = "Shopping cart management APIs")
@SecurityRequirement(name = "bearerAuth")
public class CartController {
    @Autowired
    private CartService cartService;
    
    @Operation(summary = "Add item to cart")
    @PostMapping("/add")
    public ResponseEntity<CartItem> addToCart(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody CartItemRequest request) {
        return ResponseEntity.ok(cartService.addToCart(
            userDetails.getUsername(), 
            request.getProductId(), 
            request.getQuantity()));
    }
    
    @Operation(summary = "Get user's cart items")
    @GetMapping
    public ResponseEntity<List<CartItem>> getCart(@AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(cartService.getCartItems(userDetails.getUsername()));
    }
    
    @Operation(summary = "Update cart item quantity")
    @PutMapping("/{cartItemId}")
    public ResponseEntity<?> updateCartItem(
            @AuthenticationPrincipal UserDetails userDetails,
            @Parameter(description = "Cart item ID") @PathVariable Long cartItemId,
            @Valid @RequestBody CartItemRequest request) {
        cartService.updateCartItemQuantity(
            userDetails.getUsername(), 
            cartItemId, 
            request.getQuantity());
        return ResponseEntity.ok().build();
    }
    
    @Operation(summary = "Remove item from cart")
    @DeleteMapping("/{cartItemId}")
    public ResponseEntity<?> removeFromCart(
            @AuthenticationPrincipal UserDetails userDetails,
            @Parameter(description = "Cart item ID") @PathVariable Long cartItemId) {
        cartService.removeFromCart(userDetails.getUsername(), cartItemId);
        return ResponseEntity.ok().build();
    }
    
    @Operation(summary = "Clear cart")
    @DeleteMapping
    public ResponseEntity<?> clearCart(@AuthenticationPrincipal UserDetails userDetails) {
        cartService.clearCart(userDetails.getUsername());
        return ResponseEntity.ok().build();
    }
} 