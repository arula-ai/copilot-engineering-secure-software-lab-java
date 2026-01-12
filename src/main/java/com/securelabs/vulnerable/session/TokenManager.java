package com.securelabs.vulnerable.session;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;

import java.util.*;

/**
 * VULNERABLE: Token Manager (JWT)
 *
 * This file contains INTENTIONAL security vulnerabilities for training purposes.
 * DO NOT use these patterns in production code.
 *
 * Vulnerabilities:
 * - A02: Weak JWT secret
 * - A02: Accepting 'none' algorithm
 * - A08: No token expiration validation
 * - A02: Algorithm confusion vulnerability
 */
public class TokenManager {

    // VULNERABLE: Hardcoded weak secret
    private static final String SECRET_KEY = "secret";

    // VULNERABLE: Another weak secret
    private static final String ANOTHER_SECRET = "password123";

    /**
     * VULNERABLE: Create JWT with weak secret
     */
    public static String createToken(String userId, String role) {
        // VULNERABLE: Using weak secret key
        // VULNERABLE: No expiration set

        Map<String, Object> claims = new HashMap<>();
        claims.put("userId", userId);
        claims.put("role", role);
        claims.put("isAdmin", "admin".equals(role));

        return Jwts.builder()
            .setClaims(claims)
            .setSubject(userId)
            .setIssuedAt(new Date())
            // VULNERABLE: No expiration - .setExpiration() not called
            .signWith(Keys.hmacShaKeyFor(SECRET_KEY.getBytes()), Jwts.SIG.HS256)
            .compact();
    }

    /**
     * VULNERABLE: Verify token with algorithm confusion risk
     */
    public static Map<String, Object> verifyToken(String token) {
        try {
            // VULNERABLE: Accepts any algorithm including 'none'
            // In older jjwt versions or misconfigured setups

            Claims claims = Jwts.parser()
                .setSigningKey(SECRET_KEY.getBytes())
                .build()
                .parseClaimsJws(token)
                .getBody();

            return new HashMap<>(claims);

        } catch (Exception e) {
            // VULNERABLE: Exposes internal error details
            System.out.println("Token verification failed: " + e.getMessage());
            return null;
        }
    }

    /**
     * VULNERABLE: Manual JWT parsing without proper validation
     */
    public static Map<String, Object> unsafeParseToken(String token) {
        // VULNERABLE: Parses JWT without signature verification
        String[] parts = token.split("\\.");

        if (parts.length < 2) {
            return null;
        }

        // VULNERABLE: Decodes payload without verifying signature
        String payload = new String(Base64.getUrlDecoder().decode(parts[1]));

        System.out.println("Parsed token payload: " + payload);

        // VULNERABLE: Returns unverified claims
        // Attacker can modify payload and it will be accepted
        try {
            // Simple JSON parsing (in real code would use Jackson/Gson)
            Map<String, Object> claims = new HashMap<>();
            payload = payload.substring(1, payload.length() - 1); // Remove { }
            for (String pair : payload.split(",")) {
                String[] kv = pair.split(":");
                if (kv.length == 2) {
                    String key = kv[0].replace("\"", "").trim();
                    String value = kv[1].replace("\"", "").trim();
                    claims.put(key, value);
                }
            }
            return claims;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * VULNERABLE: Token creation with 'none' algorithm
     */
    public static String createUnsignedToken(String userId, String role) {
        // VULNERABLE: Creates token with no signature
        String header = Base64.getUrlEncoder().encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes());
        String payload = Base64.getUrlEncoder().encodeToString(
            String.format("{\"userId\":\"%s\",\"role\":\"%s\",\"isAdmin\":%s}",
                userId, role, "admin".equals(role)).getBytes()
        );

        // VULNERABLE: No signature
        return header + "." + payload + ".";
    }

    /**
     * VULNERABLE: Refresh token without proper validation
     */
    public static String refreshToken(String oldToken) {
        // VULNERABLE: Doesn't verify old token is valid
        // VULNERABLE: Doesn't check if token is expired
        // VULNERABLE: Doesn't invalidate old token

        Map<String, Object> claims = unsafeParseToken(oldToken);
        if (claims == null) {
            return null;
        }

        String userId = (String) claims.get("userId");
        String role = (String) claims.get("role");

        // VULNERABLE: Creates new token from unverified claims
        return createToken(userId, role);
    }

    /**
     * VULNERABLE: Password reset token with predictable value
     */
    public static String createResetToken(String email) {
        // VULNERABLE: Predictable token based on timestamp and email
        long timestamp = System.currentTimeMillis();
        String data = email + ":" + timestamp;

        // VULNERABLE: MD5 is not secure for tokens
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(data.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            // VULNERABLE: Returns predictable fallback
            return Base64.getEncoder().encodeToString(data.getBytes());
        }
    }

    /**
     * VULNERABLE: API key generation with weak randomness
     */
    public static String generateApiKey() {
        // VULNERABLE: Using Math.random() instead of SecureRandom
        StringBuilder key = new StringBuilder("api_");
        Random random = new Random(); // VULNERABLE: Not cryptographically secure

        for (int i = 0; i < 32; i++) {
            key.append(Integer.toHexString(random.nextInt(16)));
        }

        return key.toString();
    }

    /**
     * VULNERABLE: Token storage in logs
     */
    public static void logTokenUsage(String token, String action) {
        // VULNERABLE: Logging full token
        System.out.println("Token used for " + action + ": " + token);
    }
}
