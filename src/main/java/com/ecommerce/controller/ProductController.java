package com.ecommerce.controller;

import com.ecommerce.dto.ProductRequest;
import com.ecommerce.model.Product;
import com.ecommerce.service.ProductService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/api/products")
@Tag(name = "Product", description = "Product management APIs")
public class ProductController {
    @Autowired
    private ProductService productService;
    
    @Operation(summary = "Get all products")
    @GetMapping
    public ResponseEntity<List<Product>> getAllProducts() {
        return ResponseEntity.ok(productService.getAllProducts());
    }
    
    @Operation(summary = "Get product by ID")
    @GetMapping("/{id}")
    public ResponseEntity<Product> getProduct(
            @Parameter(description = "Product ID") @PathVariable Long id) {
        return ResponseEntity.ok(productService.getProduct(id));
    }
    
    @Operation(summary = "Get products by category")
    @GetMapping("/category/{category}")
    public ResponseEntity<List<Product>> getProductsByCategory(
            @Parameter(description = "Category name") @PathVariable String category) {
        return ResponseEntity.ok(productService.getProductsByCategory(category));
    }
    
    @Operation(summary = "Get sorted products")
    @GetMapping("/sort")
    public ResponseEntity<List<Product>> getSortedProducts(
            @Parameter(description = "Sort field (price/name)") @RequestParam String sortBy,
            @Parameter(description = "Sort direction") @RequestParam(defaultValue = "true") boolean ascending) {
        List<Product> products;
        if ("price".equals(sortBy)) {
            products = productService.getProductsSortedByPrice(ascending);
        } else if ("name".equals(sortBy)) {
            products = productService.getProductsSortedByName(ascending);
        } else {
            products = productService.getAllProducts();
        }
        return ResponseEntity.ok(products);
    }
    
    @Operation(summary = "Search products")
    @GetMapping("/search")
    public ResponseEntity<List<Product>> searchProducts(
            @Parameter(description = "Search keyword") @RequestParam String keyword) {
        return ResponseEntity.ok(productService.searchProducts(keyword));
    }
    
    @Operation(summary = "Create new product", security = @SecurityRequirement(name = "bearerAuth"))
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Product> createProduct(@Valid @RequestBody ProductRequest productRequest) {
        Product product = new Product();
        product.setName(productRequest.getName());
        product.setDescription(productRequest.getDescription());
        product.setPrice(productRequest.getPrice());
        product.setStock(productRequest.getStock());
        product.setCategory(productRequest.getCategory());
        product.setBrand(productRequest.getBrand());
        
        return ResponseEntity.ok(productService.createProduct(product));
    }
    
    @Operation(summary = "Update product", security = @SecurityRequirement(name = "bearerAuth"))
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Product> updateProduct(
            @Parameter(description = "Product ID") @PathVariable Long id,
            @Valid @RequestBody ProductRequest productRequest) {
        Product product = new Product();
        product.setName(productRequest.getName());
        product.setDescription(productRequest.getDescription());
        product.setPrice(productRequest.getPrice());
        product.setStock(productRequest.getStock());
        product.setCategory(productRequest.getCategory());
        product.setBrand(productRequest.getBrand());
        
        return ResponseEntity.ok(productService.updateProduct(id, product));
    }
    
    @Operation(summary = "Delete product", security = @SecurityRequirement(name = "bearerAuth"))
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteProduct(
            @Parameter(description = "Product ID") @PathVariable Long id) {
        productService.deleteProduct(id);
        return ResponseEntity.ok().build();
    }
    
    @Operation(summary = "Upload product image", security = @SecurityRequirement(name = "bearerAuth"))
    @PostMapping("/{id}/image")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Product> uploadProductImage(
            @Parameter(description = "Product ID") @PathVariable Long id,
            @Parameter(description = "Image file") @RequestParam("file") MultipartFile file) {
        return ResponseEntity.ok(productService.updateProductImage(id, file));
    }
} 