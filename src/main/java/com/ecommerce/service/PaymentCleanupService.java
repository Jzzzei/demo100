package com.ecommerce.service;

import com.ecommerce.model.PaymentStatus;
import com.ecommerce.repository.PaymentRepository;
import com.ecommerce.config.PaymentConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;

@Service
public class PaymentCleanupService {
    @Autowired
    private PaymentRepository paymentRepository;
    
    @Autowired
    private PaymentConfig paymentConfig;
    
    @Scheduled(fixedRate = 60000) // 每分钟执行一次
    @Transactional
    public void cleanupPendingPayments() {
        LocalDateTime timeoutThreshold = LocalDateTime.now()
            .minusSeconds(paymentConfig.getTimeoutSeconds());
            
        paymentRepository.findByStatusAndPaymentDateBefore(PaymentStatus.PENDING, timeoutThreshold)
            .forEach(payment -> {
                payment.setStatus(PaymentStatus.FAILED);
                payment.setFailureReason("Payment timeout");
                paymentRepository.save(payment);
            });
    }
} 