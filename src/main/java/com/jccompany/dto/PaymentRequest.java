package com.jccompany.dto;

import jakarta.validation.constraints.*;
import java.math.BigDecimal;

public class PaymentRequest {

    @NotNull
    private Long customerId;

    @NotNull
    @Positive
    @DecimalMax("1000000.00")
    private BigDecimal amount;

    @NotBlank
    @Size(min = 3, max = 3)
    @Pattern(regexp = "^[A-Z]{3}$", message = "Currency must be 3 uppercase letters")
    private String currency;

    @Size(max = 255)
    private String description;

    public Long getCustomerId() { return customerId; }
    public void setCustomerId(Long customerId) { this.customerId = customerId; }

    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal amount) { this.amount = amount; }

    public String getCurrency() { return currency; }
    public void setCurrency(String currency) { this.currency = currency; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
}
