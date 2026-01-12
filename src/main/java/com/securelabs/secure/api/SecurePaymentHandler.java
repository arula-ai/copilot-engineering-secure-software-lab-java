package com.securelabs.secure.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * SECURE: Payment Handler
 *
 * Security Patterns Implemented:
 * - A04: Input validation for business logic
 * - A09: PCI-compliant logging (no card data)
 * - A01: Authorization checks on all endpoints
 * - A08: Webhook signature verification
 *
 * REFERENCE IMPLEMENTATION - Use as model for Lab 3
 */
@RestController
@RequestMapping("/api/secure/payments")
public class SecurePaymentHandler {

    private static final Map<String, Transaction> transactions = new ConcurrentHashMap<>();

    // SECURE: Configuration
    private static final double MAX_AMOUNT = 1_000_000.0;
    private static final Set<String> ALLOWED_CURRENCIES = Set.of("USD", "EUR", "GBP");
    private static final String WEBHOOK_SECRET = System.getenv("WEBHOOK_SECRET"); // From environment
    private static final long MAX_TIMESTAMP_AGE_MS = 5 * 60 * 1000; // 5 minutes

    /**
     * SECURE: Process payment with full validation
     */
    @PostMapping("/process")
    public ResponseEntity<?> processPayment(@RequestBody PaymentRequest request,
                                            @RequestHeader(value = "Authorization", required = false) String auth) {
        // SECURE: Require authentication
        String userId = validateAuth(auth);
        if (userId == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        // SECURE: Validate amount
        if (request.getAmount() <= 0) {
            return ResponseEntity.status(400).body(Map.of("error", "Amount must be positive"));
        }
        if (request.getAmount() > MAX_AMOUNT) {
            return ResponseEntity.status(400).body(Map.of("error", "Amount exceeds maximum allowed"));
        }
        // SECURE: Validate decimal places (2 max for currency)
        if (Math.round(request.getAmount() * 100) / 100.0 != request.getAmount()) {
            return ResponseEntity.status(400).body(Map.of("error", "Invalid amount precision"));
        }

        // SECURE: Validate currency
        if (!ALLOWED_CURRENCIES.contains(request.getCurrency())) {
            return ResponseEntity.status(400).body(Map.of(
                "error", "Invalid currency",
                "allowedCurrencies", ALLOWED_CURRENCIES
            ));
        }

        // SECURE: Validate payment token format (not raw card number)
        String paymentToken = request.getPaymentToken();
        if (paymentToken == null || !paymentToken.matches("^tok_[a-zA-Z0-9]{20,}$")) {
            return ResponseEntity.status(400).body(Map.of("error", "Invalid payment token format"));
        }

        String transactionId = "txn_" + UUID.randomUUID().toString();

        Transaction transaction = new Transaction();
        transaction.setId(transactionId);
        transaction.setAmount(request.getAmount());
        transaction.setCurrency(request.getCurrency());
        transaction.setCardLastFour(request.getCardLastFour()); // SECURE: Only store last 4
        transaction.setUserId(userId);
        transaction.setStatus("completed");
        transaction.setTimestamp(Instant.now());

        transactions.put(transactionId, transaction);

        // SECURE: Log without sensitive data
        logSecurityEvent("PAYMENT_PROCESSED", userId, Map.of(
            "transactionId", transactionId,
            "amount", request.getAmount(),
            "currency", request.getCurrency()
            // SECURE: No card number, no CVV, no token
        ));

        return ResponseEntity.ok(Map.of(
            "success", true,
            "transactionId", transactionId,
            "amount", request.getAmount(),
            "currency", request.getCurrency(),
            "cardLastFour", request.getCardLastFour(),
            "status", "completed"
            // SECURE: No full card number returned
        ));
    }

    /**
     * SECURE: Refund with authorization check
     */
    @PostMapping("/refund")
    public ResponseEntity<?> processRefund(@RequestBody RefundRequest request,
                                           @RequestHeader(value = "Authorization", required = false) String auth) {
        // SECURE: Require authentication
        String userId = validateAuth(auth);
        if (userId == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        Transaction transaction = transactions.get(request.getTransactionId());

        if (transaction == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Transaction not found"));
        }

        // SECURE: Authorization check - verify user owns the transaction
        if (!transaction.getUserId().equals(userId) && !isAdmin(userId)) {
            logSecurityEvent("UNAUTHORIZED_REFUND_ATTEMPT", userId, Map.of(
                "transactionId", request.getTransactionId(),
                "transactionOwner", transaction.getUserId()
            ));
            return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
        }

        // SECURE: Validate refund amount doesn't exceed original
        if (request.getAmount() > transaction.getAmount()) {
            return ResponseEntity.status(400).body(Map.of(
                "error", "Refund amount cannot exceed original transaction amount"
            ));
        }

        // SECURE: Check transaction hasn't already been refunded
        if ("refunded".equals(transaction.getStatus())) {
            return ResponseEntity.status(400).body(Map.of("error", "Transaction already refunded"));
        }

        transaction.setStatus("refunded");

        logSecurityEvent("REFUND_PROCESSED", userId, Map.of(
            "transactionId", request.getTransactionId(),
            "refundAmount", request.getAmount()
        ));

        return ResponseEntity.ok(Map.of(
            "success", true,
            "transactionId", request.getTransactionId(),
            "refundAmount", request.getAmount()
        ));
    }

    /**
     * SECURE: Webhook with signature verification
     */
    @PostMapping("/webhook")
    public ResponseEntity<?> handleWebhook(@RequestBody String payload,
                                           @RequestHeader("X-Webhook-Signature") String signature,
                                           @RequestHeader("X-Webhook-Timestamp") String timestamp) {
        // SECURE: Validate timestamp to prevent replay attacks
        try {
            long webhookTimestamp = Long.parseLong(timestamp);
            long now = System.currentTimeMillis();
            if (Math.abs(now - webhookTimestamp) > MAX_TIMESTAMP_AGE_MS) {
                logSecurityEvent("WEBHOOK_EXPIRED_TIMESTAMP", null, Map.of("timestamp", timestamp));
                return ResponseEntity.status(400).body(Map.of("error", "Timestamp expired"));
            }
        } catch (NumberFormatException e) {
            return ResponseEntity.status(400).body(Map.of("error", "Invalid timestamp"));
        }

        // SECURE: Verify HMAC signature
        String expectedSignature = computeHmacSignature(timestamp + "." + payload, WEBHOOK_SECRET);
        if (!timingSafeEquals(signature, expectedSignature)) {
            logSecurityEvent("WEBHOOK_INVALID_SIGNATURE", null, Map.of());
            return ResponseEntity.status(401).body(Map.of("error", "Invalid signature"));
        }

        // Process webhook (signature verified)
        logSecurityEvent("WEBHOOK_RECEIVED", null, Map.of("payloadSize", payload.length()));

        return ResponseEntity.ok(Map.of("received", true));
    }

    /**
     * SECURE: Get transaction with authorization
     */
    @GetMapping("/transactions/{transactionId}")
    public ResponseEntity<?> getTransaction(@PathVariable String transactionId,
                                            @RequestHeader(value = "Authorization", required = false) String auth) {
        // SECURE: Require authentication
        String userId = validateAuth(auth);
        if (userId == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        Transaction transaction = transactions.get(transactionId);

        if (transaction == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Transaction not found"));
        }

        // SECURE: Authorization check
        if (!transaction.getUserId().equals(userId) && !isAdmin(userId)) {
            return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
        }

        // SECURE: Return sanitized data
        return ResponseEntity.ok(Map.of(
            "id", transaction.getId(),
            "amount", transaction.getAmount(),
            "currency", transaction.getCurrency(),
            "cardLastFour", transaction.getCardLastFour(),
            "status", transaction.getStatus(),
            "timestamp", transaction.getTimestamp().toString()
            // SECURE: No full card number, no CVV
        ));
    }

    // SECURE: HMAC signature computation
    private String computeHmacSignature(String data, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            mac.init(secretKey);
            byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    // SECURE: Timing-safe string comparison
    private boolean timingSafeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(aBytes, bBytes);
    }

    private String validateAuth(String auth) {
        // Simplified - in production use proper token validation
        if (auth != null && auth.startsWith("Bearer ")) {
            return "user-" + auth.substring(7, Math.min(17, auth.length()));
        }
        return null;
    }

    private boolean isAdmin(String userId) {
        // Simplified - in production check against user store
        return userId != null && userId.contains("admin");
    }

    private void logSecurityEvent(String event, String userId, Map<String, Object> details) {
        Map<String, Object> logEntry = new LinkedHashMap<>();
        logEntry.put("timestamp", Instant.now().toString());
        logEntry.put("event", event);
        logEntry.put("userId", userId != null ? userId : "system");
        logEntry.putAll(details);
        System.out.println("SECURITY_EVENT: " + logEntry);
    }

    // Request/Response classes
    static class PaymentRequest {
        private String paymentToken;
        private String cardLastFour;
        private double amount;
        private String currency;

        public String getPaymentToken() { return paymentToken; }
        public void setPaymentToken(String paymentToken) { this.paymentToken = paymentToken; }
        public String getCardLastFour() { return cardLastFour; }
        public void setCardLastFour(String cardLastFour) { this.cardLastFour = cardLastFour; }
        public double getAmount() { return amount; }
        public void setAmount(double amount) { this.amount = amount; }
        public String getCurrency() { return currency; }
        public void setCurrency(String currency) { this.currency = currency; }
    }

    static class RefundRequest {
        private String transactionId;
        private double amount;

        public String getTransactionId() { return transactionId; }
        public void setTransactionId(String transactionId) { this.transactionId = transactionId; }
        public double getAmount() { return amount; }
        public void setAmount(double amount) { this.amount = amount; }
    }

    static class Transaction {
        private String id;
        private double amount;
        private String currency;
        private String cardLastFour;
        private String userId;
        private String status;
        private Instant timestamp;

        public String getId() { return id; }
        public void setId(String id) { this.id = id; }
        public double getAmount() { return amount; }
        public void setAmount(double amount) { this.amount = amount; }
        public String getCurrency() { return currency; }
        public void setCurrency(String currency) { this.currency = currency; }
        public String getCardLastFour() { return cardLastFour; }
        public void setCardLastFour(String cardLastFour) { this.cardLastFour = cardLastFour; }
        public String getUserId() { return userId; }
        public void setUserId(String userId) { this.userId = userId; }
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        public Instant getTimestamp() { return timestamp; }
        public void setTimestamp(Instant timestamp) { this.timestamp = timestamp; }
    }
}
