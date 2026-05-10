package com.jccompany.controller;

import com.jccompany.dto.PaymentRequest;
import com.jccompany.model.Payment;
import com.jccompany.service.PaymentService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/api/v1/payments")
public class PaymentController {

    private final PaymentService paymentService;

    public PaymentController(PaymentService paymentService) {
        this.paymentService = paymentService;
    }

    // SI-10: @Valid 입력 검증
    @PostMapping
    public ResponseEntity<Payment> createPayment(
            @Valid @RequestBody PaymentRequest request,
            @AuthenticationPrincipal UserDetails userDetails) {
        Long customerId = Long.parseLong(userDetails.getUsername());
        Payment payment = paymentService.createPayment(request, customerId);
        return ResponseEntity.status(HttpStatus.CREATED).body(payment);
    }

    @GetMapping("/customer/{customerId}")
    public ResponseEntity<List<Payment>> getCustomerPayments(
            @PathVariable Long customerId,
            @AuthenticationPrincipal UserDetails userDetails) {
        Long authenticatedCustomerId = Long.parseLong(userDetails.getUsername());
        List<Payment> payments = paymentService.getPaymentsByCustomer(customerId, authenticatedCustomerId);
        return ResponseEntity.ok(payments);
    }

    @GetMapping("/{paymentId}")
    public ResponseEntity<Payment> getPayment(
            @PathVariable Long paymentId,
            @AuthenticationPrincipal UserDetails userDetails) {
        Long authenticatedCustomerId = Long.parseLong(userDetails.getUsername());
        Payment payment = paymentService.getPaymentById(paymentId, authenticatedCustomerId);
        return ResponseEntity.ok(payment);
    }
}
