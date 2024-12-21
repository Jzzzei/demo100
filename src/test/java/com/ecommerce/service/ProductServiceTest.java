package com.ecommerce.service;

import com.ecommerce.model.Product;
import com.ecommerce.repository.ProductRepository;
import com.ecommerce.exception.ResourceNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.web.multipart.MultipartFile;

import java.math.BigDecimal;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.junit.jupiter.api.Assertions.*;

class ProductServiceTest {
    @Mock
    private ProductRepository productRepository;
    
    @InjectMocks
    private ProductService productService;
    
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }
    
    @Test
    void getAllProducts_ShouldReturnAllProducts() {
        // Arrange
        Product product1 = new Product();
        product1.setId(1L);
        product1.setName("Product 1");
        
        Product product2 = new Product();
        product2.setId(2L);
        product2.setName("Product 2");
        
        when(productRepository.findAll()).thenReturn(Arrays.asList(product1, product2));
        
        // Act
        List<Product> products = productService.getAllProducts();
        
        // Assert
        assertEquals(2, products.size());
        verify(productRepository, times(1)).findAll();
    }
    
    @Test
    void getProduct_WithValidId_ShouldReturnProduct() {
        // Arrange
        Product product = new Product();
        product.setId(1L);
        product.setName("Test Product");
        
        when(productRepository.findById(1L)).thenReturn(Optional.of(product));
        
        // Act
        Product result = productService.getProduct(1L);
        
        // Assert
        assertNotNull(result);
        assertEquals("Test Product", result.getName());
        verify(productRepository, times(1)).findById(1L);
    }
    
    @Test
    void getProduct_WithInvalidId_ShouldThrowException() {
        // Arrange
        when(productRepository.findById(1L)).thenReturn(Optional.empty());
        
        // Act & Assert
        assertThrows(ResourceNotFoundException.class, () -> {
            productService.getProduct(1L);
        });
        verify(productRepository, times(1)).findById(1L);
    }
    
    @Test
    void updateStock_WithValidQuantity_ShouldUpdateStock() {
        // Arrange
        Product product = new Product();
        product.setId(1L);
        product.setName("Test Product");
        product.setStock(10);
        
        when(productRepository.findById(1L)).thenReturn(Optional.of(product));
        when(productRepository.save(any(Product.class))).thenReturn(product);
        
        // Act
        Product result = productService.updateStock(1L, 5);
        
        // Assert
        assertEquals(15, result.getStock());
        verify(productRepository, times(1)).save(product);
    }
    
    @Test
    void searchProducts_ShouldReturnMatchingProducts() {
        // Arrange
        Product product1 = new Product();
        product1.setName("iPhone 12");
        
        Product product2 = new Product();
        product2.setName("iPhone 13");
        
        when(productRepository.findByNameContainingIgnoreCase("iPhone"))
            .thenReturn(Arrays.asList(product1, product2));
        
        // Act
        List<Product> results = productService.searchProducts("iPhone");
        
        // Assert
        assertEquals(2, results.size());
        verify(productRepository, times(1)).findByNameContainingIgnoreCase("iPhone");
    }
} 