package com.ecommerce.repository;

import com.ecommerce.model.Payment;
import com.ecommerce.model.PaymentStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface PaymentRepository extends JpaRepository<Payment, Long> {
    Optional<Payment> findByOrderId(Long orderId);
    long countByOrderId(Long orderId);
    List<Payment> findByStatusAndPaymentDateBefore(PaymentStatus status, LocalDateTime date);
} 