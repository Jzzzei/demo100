package com.ecommerce.service;

import com.ecommerce.model.CartItem;
import com.ecommerce.model.Product;
import com.ecommerce.model.User;
import com.ecommerce.repository.CartItemRepository;
import com.ecommerce.exception.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Slf4j
@Service
@Transactional
public class CartService {
    @Autowired
    private CartItemRepository cartItemRepository;
    
    @Autowired
    private ProductService productService;
    
    @Autowired
    private UserService userService;
    
    public CartItem addToCart(String username, Long productId, Integer quantity) {
        log.info("Adding product {} to cart for user: {}", productId, username);
        User user = userService.findByUsername(username);
        Product product = productService.getProduct(productId);
        
        if (product.getStock() < quantity) {
            throw new InsufficientStockException("Insufficient stock for product: " + product.getName());
        }
        
        CartItem cartItem = cartItemRepository.findByUserAndProduct_Id(user, productId)
            .orElse(new CartItem());
            
        if (cartItem.getId() == null) {
            cartItem.setUser(user);
            cartItem.setProduct(product);
            cartItem.setQuantity(quantity);
            cartItem.setPrice(product.getPrice());
            log.info("Created new cart item for product: {}", product.getName());
        } else {
            int newQuantity = cartItem.getQuantity() + quantity;
            if (product.getStock() < newQuantity) {
                throw new InsufficientStockException("Insufficient stock for product: " + product.getName());
            }
            cartItem.setQuantity(newQuantity);
            log.info("Updated quantity for existing cart item: {}", product.getName());
        }
        
        return cartItemRepository.save(cartItem);
    }
    
    public List<CartItem> getCartItems(String username) {
        log.debug("Fetching cart items for user: {}", username);
        User user = userService.findByUsername(username);
        return cartItemRepository.findByUser(user);
    }
    
    public void updateCartItemQuantity(String username, Long cartItemId, Integer quantity) {
        log.info("Updating quantity for cart item: {}", cartItemId);
        CartItem cartItem = cartItemRepository.findById(cartItemId)
            .orElseThrow(() -> new ResourceNotFoundException("Cart item not found"));
            
        if (!cartItem.getUser().getUsername().equals(username)) {
            throw new UnauthorizedException("Unauthorized access to cart item");
        }
        
        if (cartItem.getProduct().getStock() < quantity) {
            throw new InsufficientStockException("Insufficient stock for product: " + cartItem.getProduct().getName());
        }
        
        cartItem.setQuantity(quantity);
        cartItemRepository.save(cartItem);
        log.info("Updated quantity for cart item: {}", cartItemId);
    }
    
    public void removeFromCart(String username, Long cartItemId) {
        log.info("Removing item from cart: {}", cartItemId);
        CartItem cartItem = cartItemRepository.findById(cartItemId)
            .orElseThrow(() -> new ResourceNotFoundException("Cart item not found"));
            
        if (!cartItem.getUser().getUsername().equals(username)) {
            throw new UnauthorizedException("Unauthorized access to cart item");
        }
        
        cartItemRepository.delete(cartItem);
        log.info("Removed item from cart: {}", cartItemId);
    }
    
    public void clearCart(String username) {
        log.info("Clearing cart for user: {}", username);
        User user = userService.findByUsername(username);
        List<CartItem> cartItems = cartItemRepository.findByUser(user);
        cartItemRepository.deleteAll(cartItems);
        log.info("Cleared cart for user: {}", username);
    }
} 