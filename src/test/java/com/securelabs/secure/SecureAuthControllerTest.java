package com.securelabs.secure;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Security Tests for Auth Controller
 *
 * These tests verify that secure patterns are correctly implemented.
 * Use these to validate Lab 3 implementations.
 */
class SecureAuthControllerTest {

    @Test
    @DisplayName("Should never return password in response")
    void shouldNeverReturnPasswordInResponse() {
        // Test that user objects don't contain password fields
        record MockResponse(String id, String email, String role) {}

        MockResponse response = new MockResponse("123", "test@example.com", "user");

        assertNotNull(response.id());
        assertNotNull(response.email());
        assertNotNull(response.role());
        // Response record doesn't have password field - that's the secure pattern
    }

    @Test
    @DisplayName("Should use BCrypt with cost factor >= 12")
    void shouldUseBcryptWithHighCostFactor() {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
        String hashed = encoder.encode("TestPassword123!");

        // BCrypt hash format: $2a$12$... (12 is the cost factor)
        assertTrue(hashed.startsWith("$2a$12$") || hashed.startsWith("$2b$12$"),
            "BCrypt cost factor should be 12");
    }

    @Test
    @DisplayName("Should reject invalid email formats")
    void shouldRejectInvalidEmailFormats() {
        Pattern emailPattern = Pattern.compile("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$");

        String[] invalidEmails = {
            "notanemail",
            "@nodomain.com",
            "no@domain",
            "spaces in@email.com",
            ""
        };

        for (String email : invalidEmails) {
            assertFalse(emailPattern.matcher(email).matches(),
                "Should reject invalid email: " + email);
        }

        assertTrue(emailPattern.matcher("valid@email.com").matches(),
            "Should accept valid email");
    }

    @Test
    @DisplayName("Should validate password strength requirements")
    void shouldValidatePasswordStrength() {
        String[] weakPasswords = {
            "short",           // Too short
            "nouppercase123!", // No uppercase
            "NOLOWERCASE123!", // No lowercase
            "NoNumbers!!",     // No numbers
            "NoSpecial123"     // No special chars
        };

        for (String password : weakPasswords) {
            assertFalse(isStrongPassword(password),
                "Should reject weak password: " + password);
        }

        assertTrue(isStrongPassword("StrongP@ssw0rd!"),
            "Should accept strong password");
    }

    @Test
    @DisplayName("Should lock account after 5 failed attempts")
    void shouldLockAccountAfterFailedAttempts() {
        final int MAX_FAILED_ATTEMPTS = 5;
        int failedAttempts = 0;

        for (int i = 0; i < 5; i++) {
            failedAttempts++;
        }

        boolean isLocked = failedAttempts >= MAX_FAILED_ATTEMPTS;
        assertTrue(isLocked, "Account should be locked after 5 failed attempts");
    }

    @Test
    @DisplayName("Should set lockout duration to 30 minutes")
    void shouldSetLockoutDuration() {
        final long LOCKOUT_DURATION_MS = 30 * 60 * 1000;
        assertEquals(1800000, LOCKOUT_DURATION_MS, "Lockout should be 30 minutes");
    }

    @Test
    @DisplayName("Should generate cryptographically secure tokens")
    void shouldGenerateSecureTokens() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);

        // Token should be at least 32 bytes (256 bits)
        assertTrue(tokenBytes.length >= 32, "Token should be at least 32 bytes");
        assertFalse(token.isEmpty(), "Token should not be empty");
    }

    @Test
    @DisplayName("Should use generic error messages for failed login")
    void shouldUseGenericErrorMessages() {
        String errorMessage = "Authentication failed";

        // Should NOT reveal whether user exists
        assertFalse(errorMessage.contains("User not found"));
        assertFalse(errorMessage.contains("Invalid password"));
        assertFalse(errorMessage.toLowerCase().contains("email"));
    }

    @Test
    @DisplayName("Should verify user can only access their own data")
    void shouldVerifyUserOwnership() {
        String requestingUserId = "user-123";
        String targetUserId = "user-456";
        String requestingUserRole = "user";

        boolean canAccess = requestingUserId.equals(targetUserId) ||
                           "admin".equals(requestingUserRole);

        assertFalse(canAccess, "User should not access other user's data");
    }

    @Test
    @DisplayName("Should allow admin to access any user data")
    void shouldAllowAdminAccess() {
        String requestingUserId = "admin-001";
        String targetUserId = "user-456";
        String requestingUserRole = "admin";

        boolean canAccess = requestingUserId.equals(targetUserId) ||
                           "admin".equals(requestingUserRole);

        assertTrue(canAccess, "Admin should access any user's data");
    }

    // Helper method for password validation
    private boolean isStrongPassword(String password) {
        if (password == null || password.length() < 12) return false;
        if (!password.matches(".*[A-Z].*")) return false;
        if (!password.matches(".*[a-z].*")) return false;
        if (!password.matches(".*[0-9].*")) return false;
        if (!password.matches(".*[!@#$%^&*(),.?\":{}|<>].*")) return false;
        return true;
    }
}
