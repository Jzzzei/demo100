package com.ecommerce.controller;

import com.ecommerce.dto.ReviewRequest;
import com.ecommerce.model.Review;
import com.ecommerce.service.ReviewService;
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
@RequestMapping("/api/reviews")
@Tag(name = "Review", description = "Product review management APIs")
public class ReviewController {
    @Autowired
    private ReviewService reviewService;
    
    @Operation(summary = "Add review to product", security = @SecurityRequirement(name = "bearerAuth"))
    @PostMapping("/products/{productId}")
    public ResponseEntity<Review> addReview(
            @AuthenticationPrincipal UserDetails userDetails,
            @Parameter(description = "Product ID") @PathVariable Long productId,
            @Valid @RequestBody ReviewRequest request) {
        return ResponseEntity.ok(reviewService.addReview(
            userDetails.getUsername(), 
            productId, 
            request.getRating(), 
            request.getComment()));
    }
    
    @Operation(summary = "Update review", security = @SecurityRequirement(name = "bearerAuth"))
    @PutMapping("/{reviewId}")
    public ResponseEntity<Review> updateReview(
            @AuthenticationPrincipal UserDetails userDetails,
            @Parameter(description = "Review ID") @PathVariable Long reviewId,
            @Valid @RequestBody ReviewRequest request) {
        return ResponseEntity.ok(reviewService.updateReview(
            userDetails.getUsername(), 
            reviewId, 
            request.getRating(), 
            request.getComment()));
    }
    
    @Operation(summary = "Delete review", security = @SecurityRequirement(name = "bearerAuth"))
    @DeleteMapping("/{reviewId}")
    public ResponseEntity<?> deleteReview(
            @AuthenticationPrincipal UserDetails userDetails,
            @Parameter(description = "Review ID") @PathVariable Long reviewId) {
        reviewService.deleteReview(userDetails.getUsername(), reviewId);
        return ResponseEntity.ok().build();
    }
    
    @Operation(summary = "Get product reviews")
    @GetMapping("/products/{productId}")
    public ResponseEntity<List<Review>> getProductReviews(
            @Parameter(description = "Product ID") @PathVariable Long productId) {
        return ResponseEntity.ok(reviewService.getProductReviews(productId));
    }
    
    @Operation(summary = "Get user's reviews", security = @SecurityRequirement(name = "bearerAuth"))
    @GetMapping("/users/me")
    public ResponseEntity<List<Review>> getUserReviews(@AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(reviewService.getUserReviews(userDetails.getUsername()));
    }
} 