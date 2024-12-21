package com.ecommerce.repository;

import com.ecommerce.model.CreditCard;
import com.ecommerce.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

@Repository
public interface CreditCardRepository extends JpaRepository<CreditCard, Long> {
    List<CreditCard> findByUser(User user);
    Optional<CreditCard> findByUserAndIsDefaultTrue(User user);
} 