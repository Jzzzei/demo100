package com.ecommerce.service;

import com.ecommerce.model.Address;
import com.ecommerce.model.CreditCard;
import com.ecommerce.model.User;
import com.ecommerce.repository.AddressRepository;
import com.ecommerce.repository.CreditCardRepository;
import com.ecommerce.exception.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

@Slf4j
@Service
@Transactional
public class UserProfileService {
    @Autowired
    private UserService userService;
    
    @Autowired
    private AddressRepository addressRepository;
    
    @Autowired
    private CreditCardRepository creditCardRepository;
    
    // 地址管理
    public Address addAddress(String username, Address address) {
        User user = userService.findByUsername(username);
        address.setUser(user);
        
        if (address.isDefault()) {
            addressRepository.findByUserAndIsDefaultTrue(user)
                .ifPresent(defaultAddress -> {
                    defaultAddress.setDefault(false);
                    addressRepository.save(defaultAddress);
                });
        }
        
        log.info("Added new address for user: {}", username);
        return addressRepository.save(address);
    }
    
    public List<Address> getUserAddresses(String username) {
        User user = userService.findByUsername(username);
        return addressRepository.findByUser(user);
    }
    
    public Address updateAddress(String username, Long addressId, Address addressDetails) {
        Address address = addressRepository.findById(addressId)
            .orElseThrow(() -> new ResourceNotFoundException("Address not found"));
            
        if (!address.getUser().getUsername().equals(username)) {
            throw new UnauthorizedException("Unauthorized access to address");
        }
        
        address.setStreet(addressDetails.getStreet());
        address.setCity(addressDetails.getCity());
        address.setState(addressDetails.getState());
        address.setCountry(addressDetails.getCountry());
        address.setZipCode(addressDetails.getZipCode());
        
        if (addressDetails.isDefault() && !address.isDefault()) {
            addressRepository.findByUserAndIsDefaultTrue(address.getUser())
                .ifPresent(defaultAddress -> {
                    defaultAddress.setDefault(false);
                    addressRepository.save(defaultAddress);
                });
            address.setDefault(true);
        }
        
        log.info("Updated address {} for user: {}", addressId, username);
        return addressRepository.save(address);
    }
    
    public void deleteAddress(String username, Long addressId) {
        Address address = addressRepository.findById(addressId)
            .orElseThrow(() -> new ResourceNotFoundException("Address not found"));
            
        if (!address.getUser().getUsername().equals(username)) {
            throw new UnauthorizedException("Unauthorized access to address");
        }
        
        if (address.isDefault()) {
            throw new BusinessException("Cannot delete default address");
        }
        
        log.info("Deleted address {} for user: {}", addressId, username);
        addressRepository.delete(address);
    }
    
    // 信用卡管理
    public CreditCard addCreditCard(String username, CreditCard creditCard) {
        User user = userService.findByUsername(username);
        creditCard.setUser(user);
        
        if (creditCard.isDefault()) {
            creditCardRepository.findByUserAndIsDefaultTrue(user)
                .ifPresent(defaultCard -> {
                    defaultCard.setDefault(false);
                    creditCardRepository.save(defaultCard);
                });
        }
        
        log.info("Added new credit card for user: {}", username);
        return creditCardRepository.save(creditCard);
    }
    
    public List<CreditCard> getUserCreditCards(String username) {
        User user = userService.findByUsername(username);
        return creditCardRepository.findByUser(user);
    }
    
    public CreditCard updateCreditCard(String username, Long cardId, CreditCard cardDetails) {
        CreditCard creditCard = creditCardRepository.findById(cardId)
            .orElseThrow(() -> new ResourceNotFoundException("Credit card not found"));
            
        if (!creditCard.getUser().getUsername().equals(username)) {
            throw new UnauthorizedException("Unauthorized access to credit card");
        }
        
        creditCard.setCardNumber(cardDetails.getCardNumber());
        creditCard.setCardHolderName(cardDetails.getCardHolderName());
        creditCard.setExpirationMonth(cardDetails.getExpirationMonth());
        creditCard.setExpirationYear(cardDetails.getExpirationYear());
        creditCard.setCvv(cardDetails.getCvv());
        
        if (cardDetails.isDefault() && !creditCard.isDefault()) {
            creditCardRepository.findByUserAndIsDefaultTrue(creditCard.getUser())
                .ifPresent(defaultCard -> {
                    defaultCard.setDefault(false);
                    creditCardRepository.save(defaultCard);
                });
            creditCard.setDefault(true);
        }
        
        log.info("Updated credit card {} for user: {}", cardId, username);
        return creditCardRepository.save(creditCard);
    }
    
    public void deleteCreditCard(String username, Long cardId) {
        CreditCard creditCard = creditCardRepository.findById(cardId)
            .orElseThrow(() -> new ResourceNotFoundException("Credit card not found"));
            
        if (!creditCard.getUser().getUsername().equals(username)) {
            throw new UnauthorizedException("Unauthorized access to credit card");
        }
        
        if (creditCard.isDefault()) {
            throw new BusinessException("Cannot delete default credit card");
        }
        
        log.info("Deleted credit card {} for user: {}", cardId, username);
        creditCardRepository.delete(creditCard);
    }
} 