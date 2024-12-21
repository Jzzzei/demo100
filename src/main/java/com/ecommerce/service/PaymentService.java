package com.ecommerce.service;

import com.ecommerce.dto.PaymentResponse;
import com.ecommerce.model.*;
import com.ecommerce.repository.PaymentRepository;
import com.ecommerce.config.PaymentConfig;
import com.ecommerce.exception.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

@Slf4j
@Service
@Transactional
public class PaymentService {
    @Autowired
    private PaymentRepository paymentRepository;
    
    @Autowired
    private OrderService orderService;
    
    @Autowired
    private PaymentConfig paymentConfig;
    
    private static int paymentCounter = 0;
    
    public PaymentResponse processPayment(Long orderId, String paymentMethod) {
        log.info("Processing payment for order: {}", orderId);
        Order order = orderService.getOrder(orderId);
        validatePayment(order);
        
        Payment payment = createPayment(order, paymentMethod);
        processPaymentLogic(payment, order);
        
        log.info("Payment processed for order: {}, status: {}", orderId, payment.getStatus());
        return createPaymentResponse(payment);
    }
    
    private void validatePayment(Order order) {
        if (order.getStatus() != OrderStatus.PENDING) {
            throw new PaymentException("Order is not in PENDING status");
        }
        
        if (order.getTotalAmount().compareTo(paymentConfig.getMaxAmount()) > 0) {
            throw new PaymentException("Order amount exceeds maximum allowed payment");
        }
        
        paymentRepository.findByOrderId(order.getId())
            .ifPresent(existingPayment -> {
                if (existingPayment.getStatus() == PaymentStatus.PENDING) {
                    LocalDateTime timeout = existingPayment.getPaymentDate()
                        .plusSeconds(paymentConfig.getTimeoutSeconds());
                    if (LocalDateTime.now().isBefore(timeout)) {
                        throw new PaymentException("Previous payment is still processing");
                    }
                }
            });
    }
    
    private Payment createPayment(Order order, String paymentMethod) {
        Payment payment = new Payment();
        payment.setOrder(order);
        payment.setAmount(order.getTotalAmount());
        payment.setPaymentMethod(paymentMethod);
        payment.setPaymentDate(LocalDateTime.now());
        payment.setTransactionId(UUID.randomUUID().toString());
        payment.setStatus(PaymentStatus.PENDING);
        return paymentRepository.save(payment);
    }
    
    private void processPaymentLogic(Payment payment, Order order) {
        paymentCounter++;
        if (paymentCounter % 3 == 0) {
            payment.setStatus(PaymentStatus.FAILED);
            payment.setFailureReason("Payment declined by bank");
            order.setStatus(OrderStatus.CANCELLED);
            log.warn("Payment failed for order: {}", order.getId());
        } else {
            payment.setStatus(PaymentStatus.SUCCESS);
            order.setStatus(OrderStatus.PAID);
            log.info("Payment successful for order: {}", order.getId());
        }
        
        orderService.updateOrderStatus(order.getId(), order.getStatus());
        paymentRepository.save(payment);
    }
    
    public PaymentResponse retryPayment(Long orderId, String paymentMethod) {
        log.info("Retrying payment for order: {}", orderId);
        Order order = orderService.getOrder(orderId);
        Payment lastPayment = paymentRepository.findByOrderId(orderId)
            .orElseThrow(() -> new ResourceNotFoundException("No previous payment found"));
        
        long retryCount = paymentRepository.countByOrderId(orderId);
        if (retryCount >= paymentConfig.getMaxRetries()) {
            throw new PaymentException("Maximum retry attempts exceeded");
        }
        
        if (lastPayment.getStatus() != PaymentStatus.FAILED) {
            throw new PaymentException("Previous payment was not failed");
        }
        
        return processPayment(orderId, paymentMethod);
    }
    
    public Payment getPayment(Long paymentId) {
        return paymentRepository.findById(paymentId)
            .orElseThrow(() -> new ResourceNotFoundException("Payment not found"));
    }
    
    public Payment getPaymentByOrder(Long orderId) {
        return paymentRepository.findByOrderId(orderId)
            .orElseThrow(() -> new ResourceNotFoundException("Payment not found for order"));
    }
    
    private PaymentResponse createPaymentResponse(Payment payment) {
        PaymentResponse response = new PaymentResponse();
        response.setStatus(payment.getStatus());
        response.setTransactionId(payment.getTransactionId());
        response.setAmount(payment.getAmount());
        response.setPaymentDate(payment.getPaymentDate());
        if (payment.getStatus() == PaymentStatus.FAILED) {
            response.setError(payment.getFailureReason());
        }
        return response;
    }
} 