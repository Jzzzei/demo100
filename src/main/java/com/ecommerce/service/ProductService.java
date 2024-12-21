package com.ecommerce.service;

import com.ecommerce.model.Product;
import com.ecommerce.repository.ProductRepository;
import com.ecommerce.exception.ResourceNotFoundException;
import com.ecommerce.exception.InsufficientStockException;
import com.ecommerce.exception.BusinessException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@Transactional
public class ProductService {
    @Autowired
    private ProductRepository productRepository;
    
    @Value("${file.upload-dir}")
    private String uploadDir;
    
    public List<Product> getAllProducts() {
        return productRepository.findAll();
    }
    
    public Product getProduct(Long id) {
        return productRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException("Product not found with id: " + id));
    }
    
    public List<Product> getProductsByCategory(String category) {
        return productRepository.findByCategory(category);
    }
    
    public Product updateStock(Long productId, Integer quantity) {
        Product product = getProduct(productId);
        int newStock = product.getStock() + quantity;
        
        if (newStock < 0) {
            throw new InsufficientStockException("Insufficient stock for product: " + product.getName());
        }
        
        product.setStock(newStock);
        log.info("Updated stock for product {}: {} -> {}", productId, product.getStock(), newStock);
        return productRepository.save(product);
    }
    
    public Product createProduct(Product product) {
        return productRepository.save(product);
    }
    
    public Product updateProduct(Long id, Product productDetails) {
        Product product = getProduct(id);
        product.setName(productDetails.getName());
        product.setDescription(productDetails.getDescription());
        product.setPrice(productDetails.getPrice());
        product.setStock(productDetails.getStock());
        product.setCategory(productDetails.getCategory());
        product.setBrand(productDetails.getBrand());
        return productRepository.save(product);
    }
    
    public void deleteProduct(Long id) {
        Product product = getProduct(id);
        productRepository.delete(product);
    }
    
    public Product updateProductImage(Long id, MultipartFile file) {
        try {
            Product product = getProduct(id);
            
            if (file.isEmpty()) {
                throw new BusinessException("File is empty");
            }
            
            Path uploadPath = Paths.get(uploadDir);
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath);
            }
            
            String filename = UUID.randomUUID().toString() + "_" + file.getOriginalFilename();
            Path filePath = uploadPath.resolve(filename);
            
            Files.copy(file.getInputStream(), filePath);
            
            product.setImageUrl("/uploads/" + filename);
            log.info("Updated image for product {}: {}", id, filename);
            return productRepository.save(product);
            
        } catch (IOException ex) {
            log.error("Failed to store file", ex);
            throw new BusinessException("Could not store file: " + ex.getMessage());
        }
    }
    
    public List<Product> getProductsSortedByPrice(boolean ascending) {
        return ascending ? 
            productRepository.findAllByOrderByPriceAsc() :
            productRepository.findAllByOrderByPriceDesc();
    }
    
    public List<Product> getProductsSortedByName(boolean ascending) {
        return ascending ? 
            productRepository.findAllByOrderByNameAsc() :
            productRepository.findAllByOrderByNameDesc();
    }
    
    public List<Product> searchProducts(String keyword) {
        return productRepository.findByNameContainingIgnoreCase(keyword);
    }
    
    public List<Product> getProductsByCategoryAndSort(String category, String sortBy, boolean ascending) {
        if ("price".equals(sortBy)) {
            return ascending ?
                productRepository.findByCategoryOrderByPriceAsc(category) :
                productRepository.findByCategoryOrderByPriceDesc(category);
        }
        return productRepository.findByCategory(category);
    }
} 