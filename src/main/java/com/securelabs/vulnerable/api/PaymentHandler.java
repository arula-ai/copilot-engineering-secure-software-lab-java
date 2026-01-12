package com.securelabs.vulnerable.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * VULNERABLE: Payment Handler
 *
 * This file contains INTENTIONAL security vulnerabilities for training purposes.
 * DO NOT use these patterns in production code.
 *
 * Vulnerabilities:
 * - A04: Insecure Design - missing business logic validation
 * - A09: Sensitive data in logs (PCI violation)
 * - A01: Missing authorization checks
 * - A08: Missing webhook signature verification
 */
@RestController
@RequestMapping("/api/payments")
public class PaymentHandler {

    private static final Map<String, Transaction> transactions = new HashMap<>();

    /**
     * VULNERABLE: Process payment with multiple security issues
     */
    @PostMapping("/process")
    public ResponseEntity<?> processPayment(@RequestBody PaymentRequest request) {
        // VULNERABLE: Logging full card number (PCI violation - A09)
        System.out.println("Processing payment - Card: " + request.getCardNumber() +
                          ", CVV: " + request.getCvv() +
                          ", Amount: " + request.getAmount());

        // VULNERABLE: No input validation on amount (A04)
        // Allows negative amounts, extremely large amounts, etc.
        double amount = request.getAmount();

        // VULNERABLE: No currency validation
        String currency = request.getCurrency();

        // VULNERABLE: No card number format validation
        String cardNumber = request.getCardNumber();

        // VULNERABLE: No authentication required
        // VULNERABLE: No rate limiting

        String transactionId = "txn_" + System.currentTimeMillis();

        Transaction transaction = new Transaction();
        transaction.setId(transactionId);
        transaction.setAmount(amount);
        transaction.setCurrency(currency);
        transaction.setCardNumber(cardNumber); // VULNERABLE: Storing full card number
        transaction.setCvv(request.getCvv()); // VULNERABLE: Storing CVV
        transaction.setUserId(request.getUserId());
        transaction.setStatus("completed");
        transaction.setTimestamp(System.currentTimeMillis());

        transactions.put(transactionId, transaction);

        // VULNERABLE: Returning sensitive card data in response
        return ResponseEntity.ok(Map.of(
            "success", true,
            "transactionId", transactionId,
            "amount", amount,
            "cardNumber", cardNumber, // VULNERABLE: Exposing full card number
            "status", "completed"
        ));
    }

    /**
     * VULNERABLE: Refund without authorization check
     */
    @PostMapping("/refund")
    public ResponseEntity<?> processRefund(@RequestBody RefundRequest request) {
        String transactionId = request.getTransactionId();
        double refundAmount = request.getAmount();

        Transaction transaction = transactions.get(transactionId);

        if (transaction == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Transaction not found"));
        }

        // VULNERABLE: No authorization check - anyone can refund any transaction
        // VULNERABLE: No check if requesting user owns the transaction
        // VULNERABLE: No check if refund amount exceeds original amount

        System.out.println("Processing refund: " + transactionId + " Amount: " + refundAmount);

        // VULNERABLE: Allows refund greater than original amount
        transaction.setStatus("refunded");

        return ResponseEntity.ok(Map.of(
            "success", true,
            "transactionId", transactionId,
            "refundAmount", refundAmount,
            "originalAmount", transaction.getAmount()
        ));
    }

    /**
     * VULNERABLE: Webhook without signature verification
     */
    @PostMapping("/webhook")
    public ResponseEntity<?> handleWebhook(@RequestBody Map<String, Object> payload,
                                           @RequestHeader Map<String, String> headers) {
        // VULNERABLE: No signature verification (A08)
        // VULNERABLE: No timestamp validation (replay attack possible)
        // VULNERABLE: No IP whitelist check

        System.out.println("Webhook received: " + payload);

        String eventType = (String) payload.get("type");
        Map<String, Object> data = (Map<String, Object>) payload.get("data");

        // VULNERABLE: Trusting webhook data without verification
        if ("payment.completed".equals(eventType)) {
            String transactionId = (String) data.get("transactionId");
            Transaction transaction = transactions.get(transactionId);
            if (transaction != null) {
                transaction.setStatus("confirmed");
            }
        }

        return ResponseEntity.ok(Map.of("received", true));
    }

    /**
     * VULNERABLE: Get transaction without authorization
     */
    @GetMapping("/transactions/{transactionId}")
    public ResponseEntity<?> getTransaction(@PathVariable String transactionId) {
        // VULNERABLE: No authentication or authorization check (A01)
        // VULNERABLE: IDOR - anyone can view any transaction

        Transaction transaction = transactions.get(transactionId);

        if (transaction == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Transaction not found"));
        }

        // VULNERABLE: Exposing full card number and CVV
        return ResponseEntity.ok(Map.of(
            "id", transaction.getId(),
            "amount", transaction.getAmount(),
            "currency", transaction.getCurrency(),
            "cardNumber", transaction.getCardNumber(),
            "cvv", transaction.getCvv(), // VULNERABLE: Exposing CVV
            "userId", transaction.getUserId(),
            "status", transaction.getStatus()
        ));
    }

    /**
     * VULNERABLE: List all transactions (admin endpoint without auth)
     */
    @GetMapping("/transactions")
    public ResponseEntity<?> listTransactions() {
        // VULNERABLE: No authentication - exposes all transactions
        // VULNERABLE: No pagination - could dump entire database

        List<Map<String, Object>> result = new ArrayList<>();
        for (Transaction t : transactions.values()) {
            result.add(Map.of(
                "id", t.getId(),
                "amount", t.getAmount(),
                "cardNumber", t.getCardNumber(), // VULNERABLE
                "userId", t.getUserId(),
                "status", t.getStatus()
            ));
        }

        return ResponseEntity.ok(result);
    }

    /**
     * VULNERABLE: Delete transaction without proper authorization
     */
    @DeleteMapping("/transactions/{transactionId}")
    public ResponseEntity<?> deleteTransaction(@PathVariable String transactionId) {
        // VULNERABLE: No audit trail
        // VULNERABLE: No authorization check

        Transaction removed = transactions.remove(transactionId);

        if (removed == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Transaction not found"));
        }

        return ResponseEntity.ok(Map.of("deleted", true, "transactionId", transactionId));
    }

    // Request/Response classes
    static class PaymentRequest {
        private String cardNumber;
        private String cvv;
        private String expiryDate;
        private double amount;
        private String currency;
        private String userId;

        public String getCardNumber() { return cardNumber; }
        public void setCardNumber(String cardNumber) { this.cardNumber = cardNumber; }
        public String getCvv() { return cvv; }
        public void setCvv(String cvv) { this.cvv = cvv; }
        public String getExpiryDate() { return expiryDate; }
        public void setExpiryDate(String expiryDate) { this.expiryDate = expiryDate; }
        public double getAmount() { return amount; }
        public void setAmount(double amount) { this.amount = amount; }
        public String getCurrency() { return currency; }
        public void setCurrency(String currency) { this.currency = currency; }
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
    }

    static class RefundRequest {
        private String transactionId;
        private double amount;
        private String reason;

        public String getTransactionId() { return transactionId; }
        public void setTransactionId(String transactionId) { this.transactionId = transactionId; }
        public double getAmount() { return amount; }
        public void setAmount(double amount) { this.amount = amount; }
        public String getReason() { return reason; }
        public void setReason(String reason) { this.reason = reason; }
    }

    static class Transaction {
        private String id;
        private double amount;
        private String currency;
        private String cardNumber;
        private String cvv;
        private String userId;
        private String status;
        private long timestamp;

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public double getAmount() { return amount; }
        public void setAmount(double amount) { this.amount = amount; }
        public String getCurrency() { return currency; }
        public void setCurrency(String currency) { this.currency = currency; }
        public String getCardNumber() { return cardNumber; }
        public void setCardNumber(String cardNumber) { this.cardNumber = cardNumber; }
        public String getCvv() { return cvv; }
        public void setCvv(String cvv) { this.cvv = cvv; }
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        public long getTimestamp() { return timestamp; }
        public void setTimestamp(long timestamp) { this.timestamp = timestamp; }
    }
}
