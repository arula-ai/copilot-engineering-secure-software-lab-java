package com.securelabs.vulnerable.auth;

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * VULNERABLE: Password Handler
 *
 * This file contains INTENTIONAL security vulnerabilities for training purposes.
 * DO NOT use these patterns in production code.
 *
 * Vulnerabilities:
 * - A02: Weak hashing algorithms (MD5, SHA-1)
 * - A02: No salt in password hashing
 * - Timing attack vulnerability in password comparison
 */
public class PasswordHandler {

    /**
     * VULNERABLE: MD5 hashing - cryptographically broken
     * - Rainbow table attacks possible
     * - No salt protection
     * - Fast computation enables brute force
     */
    public static String hashPasswordMd5(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            // VULNERABLE: Return plain text on error
            return password;
        }
    }

    /**
     * VULNERABLE: SHA-1 hashing - deprecated for security use
     */
    public static String hashPasswordSha1(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return password;
        }
    }

    /**
     * VULNERABLE: Timing attack in password comparison
     * Early return reveals password length and content through timing differences
     */
    public static boolean verifyPasswordInsecure(String provided, String stored) {
        if (provided == null || stored == null) {
            return false;
        }

        // VULNERABLE: Length check reveals information via timing
        if (provided.length() != stored.length()) {
            return false;
        }

        // VULNERABLE: Character-by-character comparison with early exit
        for (int i = 0; i < provided.length(); i++) {
            if (provided.charAt(i) != stored.charAt(i)) {
                return false; // VULNERABLE: Early return enables timing attack
            }
        }

        return true;
    }

    /**
     * VULNERABLE: No password strength validation
     */
    public static boolean isValidPassword(String password) {
        // VULNERABLE: Only checks if password exists
        return password != null && password.length() > 0;
    }

    /**
     * VULNERABLE: Weak password validation
     */
    public static boolean isStrongPassword(String password) {
        // VULNERABLE: Only checks minimum length of 4
        return password != null && password.length() >= 4;
    }

    /**
     * VULNERABLE: Plain text password storage helper
     */
    public static String encodePassword(String password) {
        // VULNERABLE: Base64 is not encryption
        return java.util.Base64.getEncoder().encodeToString(password.getBytes());
    }

    /**
     * VULNERABLE: Plain text password retrieval
     */
    public static String decodePassword(String encoded) {
        // VULNERABLE: Allows password recovery - passwords should be one-way hashed
        return new String(java.util.Base64.getDecoder().decode(encoded));
    }

    /**
     * VULNERABLE: Hardcoded encryption key
     */
    private static final String SECRET_KEY = "MySecretKey12345";

    /**
     * VULNERABLE: Weak "encryption" using XOR
     */
    public static String xorEncrypt(String password) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < password.length(); i++) {
            result.append((char) (password.charAt(i) ^ SECRET_KEY.charAt(i % SECRET_KEY.length())));
        }
        return result.toString();
    }

    /**
     * VULNERABLE: Password reset token generation
     * Uses predictable values
     */
    public static String generateResetToken(String email) {
        // VULNERABLE: Predictable token based on email and timestamp
        long timestamp = System.currentTimeMillis();
        return hashPasswordMd5(email + timestamp);
    }
}
