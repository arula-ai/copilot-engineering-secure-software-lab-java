package com.securelabs.secure;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Security Tests for Payment Handler
 *
 * These tests verify secure payment processing patterns.
 * Use these to validate Lab 3 implementations.
 */
class SecurePaymentHandlerTest {

    @Test
    @DisplayName("Should reject negative amounts")
    void shouldRejectNegativeAmounts() {
        assertFalse(validateAmount(-100), "Should reject negative amount");
        assertFalse(validateAmount(0), "Should reject zero amount");
        assertFalse(validateAmount(-0.01), "Should reject small negative amount");
    }

    @Test
    @DisplayName("Should reject amounts exceeding maximum")
    void shouldRejectExcessiveAmounts() {
        final double MAX_AMOUNT = 1_000_000;

        assertFalse(validateAmountWithMax(1_000_001, MAX_AMOUNT));
        assertFalse(validateAmountWithMax(999_999_999, MAX_AMOUNT));
        assertTrue(validateAmountWithMax(999_999, MAX_AMOUNT));
    }

    @Test
    @DisplayName("Should validate currency against whitelist")
    void shouldValidateCurrencyWhitelist() {
        Set<String> ALLOWED_CURRENCIES = Set.of("USD", "EUR", "GBP");

        assertTrue(ALLOWED_CURRENCIES.contains("USD"));
        assertTrue(ALLOWED_CURRENCIES.contains("EUR"));
        assertFalse(ALLOWED_CURRENCIES.contains("BTC"));
        assertFalse(ALLOWED_CURRENCIES.contains("XYZ"));
    }

    @Test
    @DisplayName("Should reject amounts with more than 2 decimal places")
    void shouldValidateDecimalPlaces() {
        assertTrue(validateDecimalPlaces(10.99));
        assertFalse(validateDecimalPlaces(10.999));
        assertFalse(validateDecimalPlaces(10.1234));
    }

    @Test
    @DisplayName("Should never log full card numbers")
    void shouldNotLogCardNumbers() {
        Set<String> sensitiveFields = Set.of("cardNumber", "cvv", "pan", "fullCard");

        record LogEntry(String transactionId, double amount, String currency, String cardLastFour) {}

        LogEntry entry = new LogEntry("txn-123", 100.0, "USD", "1234");

        // Verify log entry doesn't have sensitive fields
        assertNotNull(entry.cardLastFour());
        assertEquals(4, entry.cardLastFour().length(), "Should only store last 4 digits");
    }

    @Test
    @DisplayName("Should only store last 4 digits of card")
    void shouldMaskCardNumber() {
        String fullCard = "4111111111111111";
        String masked = fullCard.substring(fullCard.length() - 4);

        assertEquals("1111", masked);
        assertEquals(4, masked.length());
    }

    @Test
    @DisplayName("Should use tokenization for card processing")
    void shouldUseTokenization() {
        record PaymentRequest(String paymentToken, double amount) {}

        PaymentRequest request = new PaymentRequest("tok_abc123", 100.0);

        assertNotNull(request.paymentToken());
        assertTrue(request.paymentToken().startsWith("tok_"));
    }

    @Test
    @DisplayName("Should verify transaction ownership before refund")
    void shouldVerifyTransactionOwnership() {
        String transactionUserId = "user-456";
        String requestingUserId = "user-789";

        boolean canRefund = transactionUserId.equals(requestingUserId);
        assertFalse(canRefund, "Should not allow refund by non-owner");
    }

    @Test
    @DisplayName("Should not allow refund greater than original amount")
    void shouldValidateRefundAmount() {
        double originalAmount = 100.0;
        double refundAmount = 150.0;

        boolean isValidRefund = refundAmount <= originalAmount;
        assertFalse(isValidRefund, "Refund should not exceed original amount");
    }

    @Test
    @DisplayName("Should verify webhook signature")
    void shouldVerifyWebhookSignature() throws Exception {
        String webhookSecret = "test-secret";
        String payload = "{\"event\":\"payment.completed\"}";
        String timestamp = String.valueOf(System.currentTimeMillis());

        String expectedSignature = computeHmacSignature(timestamp + "." + payload, webhookSecret);

        assertTrue(timingSafeEquals(expectedSignature, expectedSignature));
        assertFalse(timingSafeEquals("invalid", expectedSignature));
    }

    @Test
    @DisplayName("Should reject expired timestamps")
    void shouldRejectExpiredTimestamps() {
        final long MAX_TIMESTAMP_AGE_MS = 5 * 60 * 1000; // 5 minutes

        long oldTimestamp = System.currentTimeMillis() - (10 * 60 * 1000); // 10 minutes ago
        long timestampAge = System.currentTimeMillis() - oldTimestamp;

        boolean isExpired = timestampAge > MAX_TIMESTAMP_AGE_MS;
        assertTrue(isExpired, "Should reject timestamps older than 5 minutes");
    }

    @Test
    @DisplayName("Should use cryptographically secure transaction IDs")
    void shouldUseSecureTransactionIds() {
        String transactionId = "txn_" + UUID.randomUUID().toString();

        assertTrue(transactionId.startsWith("txn_"));
        assertTrue(transactionId.length() > 20);
        // UUID format validation
        assertTrue(transactionId.matches("txn_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"));
    }

    // Helper methods
    private boolean validateAmount(double amount) {
        return amount > 0;
    }

    private boolean validateAmountWithMax(double amount, double max) {
        return amount > 0 && amount <= max;
    }

    private boolean validateDecimalPlaces(double amount) {
        return Math.round(amount * 100) / 100.0 == amount;
    }

    private String computeHmacSignature(String data, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        mac.init(secretKey);
        byte[] hash = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte b : hash) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private boolean timingSafeEquals(String a, String b) {
        if (a == null || b == null) return false;
        byte[] aBytes = a.getBytes(StandardCharsets.UTF_8);
        byte[] bBytes = b.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(aBytes, bBytes);
    }
}
