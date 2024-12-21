package com.ecommerce.service;

import com.ecommerce.model.Review;
import com.ecommerce.model.Product;
import com.ecommerce.model.User;
import com.ecommerce.repository.ReviewRepository;
import com.ecommerce.repository.ProductRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;
import java.util.List;

@Service
@Transactional
public class ReviewService {
    @Autowired
    private ReviewRepository reviewRepository;
    
    @Autowired
    private ProductService productService;
    
    @Autowired
    private UserService userService;
    
    public Review addReview(String username, Long productId, Integer rating, String comment) {
        User user = userService.findByUsername(username);
        Product product = productService.getProduct(productId);
        
        if (rating < 1 || rating > 5) {
            throw new RuntimeException("Rating must be between 1 and 5");
        }
        
        if (reviewRepository.existsByUserAndProduct(user, product)) {
            throw new RuntimeException("User has already reviewed this product");
        }
        
        Review review = new Review();
        review.setUser(user);
        review.setProduct(product);
        review.setRating(rating);
        review.setComment(comment);
        review.setCreatedAt(LocalDateTime.now());
        
        Review savedReview = reviewRepository.save(review);
        updateProductRating(product);
        
        return savedReview;
    }
    
    public Review updateReview(String username, Long reviewId, Integer rating, String comment) {
        Review review = reviewRepository.findById(reviewId)
            .orElseThrow(() -> new RuntimeException("Review not found"));
            
        if (!review.getUser().getUsername().equals(username)) {
            throw new RuntimeException("Unauthorized access to review");
        }
        
        if (rating < 1 || rating > 5) {
            throw new RuntimeException("Rating must be between 1 and 5");
        }
        
        review.setRating(rating);
        review.setComment(comment);
        
        Review updatedReview = reviewRepository.save(review);
        updateProductRating(review.getProduct());
        
        return updatedReview;
    }
    
    public void deleteReview(String username, Long reviewId) {
        Review review = reviewRepository.findById(reviewId)
            .orElseThrow(() -> new RuntimeException("Review not found"));
            
        if (!review.getUser().getUsername().equals(username)) {
            throw new RuntimeException("Unauthorized access to review");
        }
        
        Product product = review.getProduct();
        reviewRepository.delete(review);
        updateProductRating(product);
    }
    
    private void updateProductRating(Product product) {
        List<Review> reviews = reviewRepository.findByProduct(product);
        if (reviews.isEmpty()) {
            product.setAverageRating(0.0);
            product.setReviewCount(0);
        } else {
            double avgRating = reviews.stream()
                .mapToInt(Review::getRating)
                .average()
                .orElse(0.0);
            product.setAverageRating(avgRating);
            product.setReviewCount(reviews.size());
        }
        productService.updateProduct(product.getId(), product);
    }
    
    public List<Review> getProductReviews(Long productId) {
        Product product = productService.getProduct(productId);
        return reviewRepository.findByProduct(product);
    }
    
    public List<Review> getUserReviews(String username) {
        User user = userService.findByUsername(username);
        return reviewRepository.findByUser(user);
    }
} 