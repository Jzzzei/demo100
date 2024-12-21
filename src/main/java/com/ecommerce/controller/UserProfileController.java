package com.ecommerce.controller;

import com.ecommerce.dto.AddressRequest;
import com.ecommerce.dto.CreditCardRequest;
import com.ecommerce.model.Address;
import com.ecommerce.model.CreditCard;
import com.ecommerce.service.UserProfileService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/profile")
@Tag(name = "User Profile", description = "User profile management APIs")
@SecurityRequirement(name = "bearerAuth")
public class UserProfileController {
    @Autowired
    private UserProfileService userProfileService;
    
    // 地址管理
    @Operation(summary = "Add new address")
    @PostMapping("/addresses")
    public ResponseEntity<Address> addAddress(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody AddressRequest request) {
        Address address = new Address();
        address.setStreet(request.getStreet());
        address.setCity(request.getCity());
        address.setState(request.getState());
        address.setCountry(request.getCountry());
        address.setZipCode(request.getZipCode());
        address.setDefault(request.isDefault());
        
        return ResponseEntity.ok(userProfileService.addAddress(userDetails.getUsername(), address));
    }
    
    @Operation(summary = "Get user's addresses")
    @GetMapping("/addresses")
    public ResponseEntity<List<Address>> getAddresses(@AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(userProfileService.getUserAddresses(userDetails.getUsername()));
    }
    
    @Operation(summary = "Update address")
    @PutMapping("/addresses/{id}")
    public ResponseEntity<Address> updateAddress(
            @AuthenticationPrincipal UserDetails userDetails,
            @Parameter(description = "Address ID") @PathVariable Long id,
            @Valid @RequestBody AddressRequest request) {
        Address address = new Address();
        address.setStreet(request.getStreet());
        address.setCity(request.getCity());
        address.setState(request.getState());
        address.setCountry(request.getCountry());
        address.setZipCode(request.getZipCode());
        address.setDefault(request.isDefault());
        
        return ResponseEntity.ok(userProfileService.updateAddress(userDetails.getUsername(), id, address));
    }
    
    @Operation(summary = "Delete address")
    @DeleteMapping("/addresses/{id}")
    public ResponseEntity<?> deleteAddress(
            @AuthenticationPrincipal UserDetails userDetails,
            @Parameter(description = "Address ID") @PathVariable Long id) {
        userProfileService.deleteAddress(userDetails.getUsername(), id);
        return ResponseEntity.ok().build();
    }
    
    // 信用卡管理
    @Operation(summary = "Add new credit card")
    @PostMapping("/credit-cards")
    public ResponseEntity<CreditCard> addCreditCard(
            @AuthenticationPrincipal UserDetails userDetails,
            @Valid @RequestBody CreditCardRequest request) {
        CreditCard creditCard = new CreditCard();
        creditCard.setCardNumber(request.getCardNumber());
        creditCard.setCardHolderName(request.getCardHolderName());
        creditCard.setExpirationMonth(request.getExpirationMonth());
        creditCard.setExpirationYear(request.getExpirationYear());
        creditCard.setCvv(request.getCvv());
        creditCard.setDefault(request.isDefault());
        
        return ResponseEntity.ok(userProfileService.addCreditCard(userDetails.getUsername(), creditCard));
    }
    
    @Operation(summary = "Get user's credit cards")
    @GetMapping("/credit-cards")
    public ResponseEntity<List<CreditCard>> getCreditCards(@AuthenticationPrincipal UserDetails userDetails) {
        return ResponseEntity.ok(userProfileService.getUserCreditCards(userDetails.getUsername()));
    }
    
    @Operation(summary = "Update credit card")
    @PutMapping("/credit-cards/{id}")
    public ResponseEntity<CreditCard> updateCreditCard(
            @AuthenticationPrincipal UserDetails userDetails,
            @Parameter(description = "Credit card ID") @PathVariable Long id,
            @Valid @RequestBody CreditCardRequest request) {
        CreditCard creditCard = new CreditCard();
        creditCard.setCardNumber(request.getCardNumber());
        creditCard.setCardHolderName(request.getCardHolderName());
        creditCard.setExpirationMonth(request.getExpirationMonth());
        creditCard.setExpirationYear(request.getExpirationYear());
        creditCard.setCvv(request.getCvv());
        creditCard.setDefault(request.isDefault());
        
        return ResponseEntity.ok(userProfileService.updateCreditCard(userDetails.getUsername(), id, creditCard));
    }
    
    @Operation(summary = "Delete credit card")
    @DeleteMapping("/credit-cards/{id}")
    public ResponseEntity<?> deleteCreditCard(
            @AuthenticationPrincipal UserDetails userDetails,
            @Parameter(description = "Credit card ID") @PathVariable Long id) {
        userProfileService.deleteCreditCard(userDetails.getUsername(), id);
        return ResponseEntity.ok().build();
    }
} 