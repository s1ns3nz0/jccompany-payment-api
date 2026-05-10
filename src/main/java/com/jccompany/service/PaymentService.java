package com.jccompany.service;

import com.jccompany.dto.PaymentRequest;
import com.jccompany.model.Payment;
import com.jccompany.repository.PaymentRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;

@Service
@Transactional
public class PaymentService {

    private final PaymentRepository paymentRepository;

    public PaymentService(PaymentRepository paymentRepository) {
        this.paymentRepository = paymentRepository;
    }

    public Payment createPayment(PaymentRequest request, Long authenticatedCustomerId) {
        // AC-3: 인증된 고객 ID로만 결제 생성 (Broken Access Control 방어)
        Payment payment = new Payment();
        payment.setCustomerId(authenticatedCustomerId);
        payment.setAmount(request.getAmount());
        payment.setCurrency(request.getCurrency());
        payment.setDescription(request.getDescription());
        payment.setStatus("PENDING");
        return paymentRepository.save(payment);
    }

    public List<Payment> getPaymentsByCustomer(Long customerId, Long authenticatedCustomerId) {
        // AC-3: 본인 결제 내역만 조회 가능
        if (!customerId.equals(authenticatedCustomerId)) {
            throw new SecurityException("Access denied: cannot access other customer's payments");
        }
        return paymentRepository.findByCustomerId(customerId);
    }

    public Payment getPaymentById(Long paymentId, Long authenticatedCustomerId) {
        Payment payment = paymentRepository.findById(paymentId)
            .orElseThrow(() -> new RuntimeException("Payment not found"));
        // AC-3: 본인 결제만 조회 가능
        if (!payment.getCustomerId().equals(authenticatedCustomerId)) {
            throw new SecurityException("Access denied: cannot access other customer's payment");
        }
        return payment;
    }
}
