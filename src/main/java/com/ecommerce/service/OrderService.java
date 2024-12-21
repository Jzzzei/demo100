package com.ecommerce.service;

import com.ecommerce.model.*;
import com.ecommerce.repository.OrderRepository;
import com.ecommerce.exception.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Service
@Transactional
public class OrderService {
    @Autowired
    private OrderRepository orderRepository;
    
    @Autowired
    private CartService cartService;
    
    @Autowired
    private ProductService productService;
    
    public Order createOrder(String username, String shippingAddress, String paymentMethod) {
        log.info("Creating order for user: {}", username);
        List<CartItem> cartItems = cartService.getCartItems(username);
        if (cartItems.isEmpty()) {
            throw new BusinessException("Cart is empty");
        }
        
        Order order = new Order();
        order.setUser(cartItems.get(0).getUser());
        order.setOrderDate(LocalDateTime.now());
        order.setStatus(OrderStatus.PENDING);
        order.setShippingAddress(shippingAddress);
        order.setPaymentMethod(paymentMethod);
        
        BigDecimal totalAmount = BigDecimal.ZERO;
        
        // Create order items and update product stock
        for (CartItem cartItem : cartItems) {
            OrderItem orderItem = new OrderItem();
            orderItem.setOrder(order);
            orderItem.setProduct(cartItem.getProduct());
            orderItem.setQuantity(cartItem.getQuantity());
            orderItem.setPrice(cartItem.getPrice());
            
            order.getOrderItems().add(orderItem);
            
            totalAmount = totalAmount.add(cartItem.getPrice().multiply(new BigDecimal(cartItem.getQuantity())));
            
            Product product = cartItem.getProduct();
            if (product.getStock() < cartItem.getQuantity()) {
                throw new InsufficientStockException("Insufficient stock for product: " + product.getName());
            }
            productService.updateStock(product.getId(), -cartItem.getQuantity());
        }
        
        order.setTotalAmount(totalAmount);
        
        Order savedOrder = orderRepository.save(order);
        log.info("Created order: {} with total amount: {}", savedOrder.getId(), totalAmount);
        
        // Clear cart
        cartItems.forEach(cartItem -> 
            cartService.removeFromCart(username, cartItem.getId()));
        
        return savedOrder;
    }
    
    public List<Order> getUserOrders(String username) {
        log.debug("Fetching orders for user: {}", username);
        return orderRepository.findByUserOrderByOrderDateDesc(cartService.getCartItems(username).get(0).getUser());
    }
    
    public Order getOrder(Long orderId) {
        return orderRepository.findById(orderId)
            .orElseThrow(() -> new ResourceNotFoundException("Order not found with id: " + orderId));
    }
    
    public Order updateOrderStatus(Long orderId, OrderStatus status) {
        Order order = getOrder(orderId);
        order.setStatus(status);
        log.info("Updated order {} status to: {}", orderId, status);
        return orderRepository.save(order);
    }
    
    public Order confirmOrder(String username, Long orderId) {
        Order order = getOrder(orderId);
        if (!order.getUser().getUsername().equals(username)) {
            throw new UnauthorizedException("Unauthorized access to order");
        }
        
        if (order.getStatus() != OrderStatus.PENDING) {
            throw new BusinessException("Order cannot be confirmed in current status");
        }
        
        order.setStatus(OrderStatus.PAID);
        log.info("Order {} confirmed by user: {}", orderId, username);
        return orderRepository.save(order);
    }
    
    public Order cancelOrder(String username, Long orderId) {
        Order order = getOrder(orderId);
        if (!order.getUser().getUsername().equals(username)) {
            throw new UnauthorizedException("Unauthorized access to order");
        }
        
        if (order.getStatus() != OrderStatus.PENDING && order.getStatus() != OrderStatus.PAID) {
            throw new BusinessException("Order cannot be cancelled in current status");
        }
        
        // 恢复库存
        order.getOrderItems().forEach(item -> {
            productService.updateStock(item.getProduct().getId(), item.getQuantity());
        });
        
        order.setStatus(OrderStatus.CANCELLED);
        log.info("Order {} cancelled by user: {}", orderId, username);
        return orderRepository.save(order);
    }
    
    // 管理员方法
    public List<Order> getAllOrders() {
        log.debug("Fetching all orders");
        return orderRepository.findAll();
    }
    
    public Map<String, Object> getOrderStatistics() {
        log.debug("Generating order statistics");
        List<Order> orders = getAllOrders();
        Map<String, Object> stats = new HashMap<>();
        
        BigDecimal totalSales = orders.stream()
            .map(Order::getTotalAmount)
            .reduce(BigDecimal.ZERO, BigDecimal::add);
            
        Map<OrderStatus, Long> statusStats = orders.stream()
            .collect(Collectors.groupingBy(Order::getStatus, Collectors.counting()));
            
        Map<String, BigDecimal> monthlySales = orders.stream()
            .collect(Collectors.groupingBy(
                order -> order.getOrderDate().format(DateTimeFormatter.ofPattern("yyyy-MM")),
                Collectors.mapping(Order::getTotalAmount,
                    Collectors.reducing(BigDecimal.ZERO, BigDecimal::add))
            ));
        
        stats.put("totalSales", totalSales);
        stats.put("statusStats", statusStats);
        stats.put("monthlySales", monthlySales);
        stats.put("totalOrders", orders.size());
        
        log.info("Generated order statistics: total sales = {}, total orders = {}", 
            totalSales, orders.size());
        
        return stats;
    }
    
    public Map<String, Object> getOrderSummary(Long orderId) {
        Order order = getOrder(orderId);
        Map<String, Object> summary = new HashMap<>();
        
        summary.put("orderId", order.getId());
        summary.put("orderDate", order.getOrderDate());
        summary.put("status", order.getStatus());
        summary.put("totalAmount", order.getTotalAmount());
        summary.put("shippingAddress", order.getShippingAddress());
        
        List<Map<String, Object>> items = order.getOrderItems().stream()
            .map(item -> {
                Map<String, Object> itemMap = new HashMap<>();
                itemMap.put("productName", item.getProduct().getName());
                itemMap.put("quantity", item.getQuantity());
                itemMap.put("price", item.getPrice());
                itemMap.put("subtotal", item.getPrice().multiply(new BigDecimal(item.getQuantity())));
                return itemMap;
            })
            .collect(Collectors.toList());
            
        summary.put("items", items);
        log.debug("Generated order summary for order: {}", orderId);
        return summary;
    }
} 