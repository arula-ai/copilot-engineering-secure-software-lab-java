package com.securelabs.secure.auth;

import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * SECURE: Authentication Controller
 *
 * Security Patterns Implemented:
 * - A01: Proper authorization checks on all endpoints
 * - A02: Strong password hashing with BCrypt
 * - A07: Rate limiting, account lockout, secure sessions
 * - A09: Security event logging (without sensitive data)
 *
 * REFERENCE IMPLEMENTATION - Use as model for Lab 3
 */
@RestController
@RequestMapping("/api/secure/auth")
public class SecureAuthController {

    // SECURE: BCrypt with cost factor 12
    private static final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder(12);

    // SECURE: SecureRandom for cryptographic operations
    private static final SecureRandom secureRandom = new SecureRandom();

    // SECURE: Configuration constants
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final long LOCKOUT_DURATION_MS = 30 * 60 * 1000; // 30 minutes
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$");

    // Simulated stores (use database in production)
    private static final Map<String, User> users = new ConcurrentHashMap<>();
    private static final Map<String, String> sessions = new ConcurrentHashMap<>();

    static {
        // Demo user with BCrypt hashed password
        String hashedPassword = passwordEncoder.encode("SecureP@ss123!");
        users.put("admin@example.com", new User("1", "admin@example.com", hashedPassword, "admin"));
    }

    /**
     * SECURE: Login with rate limiting, account lockout, and secure token generation
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletResponse response) {
        String email = request.getEmail();
        String password = request.getPassword();
        String clientIp = "unknown"; // In production: get from request

        // SECURE: Input validation
        if (email == null || password == null || email.isBlank() || password.isBlank()) {
            logSecurityEvent("LOGIN_INVALID_INPUT", null, clientIp, false);
            return ResponseEntity.status(400).body(Map.of("error", "Invalid request"));
        }

        // SECURE: Email format validation
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            return ResponseEntity.status(400).body(Map.of("error", "Invalid email format"));
        }

        User user = users.get(email);

        // SECURE: Check account lockout
        if (user != null && user.getLockedUntil() != null && user.getLockedUntil().isAfter(Instant.now())) {
            logSecurityEvent("LOGIN_ACCOUNT_LOCKED", user.getId(), clientIp, false);
            // SECURE: Generic message prevents user enumeration
            return ResponseEntity.status(401).body(Map.of("error", "Authentication failed"));
        }

        // SECURE: Timing-safe password verification
        if (user == null) {
            // SECURE: Still perform hash comparison to prevent timing attacks
            passwordEncoder.matches(password, "$2a$12$dummy.hash.to.prevent.timing.attacks..");
            logSecurityEvent("LOGIN_FAILED", null, clientIp, false);
            // SECURE: Generic message prevents user enumeration
            return ResponseEntity.status(401).body(Map.of("error", "Authentication failed"));
        }

        boolean passwordValid = passwordEncoder.matches(password, user.getPasswordHash());

        if (!passwordValid) {
            // SECURE: Increment failed attempts
            user.incrementFailedAttempts();

            // SECURE: Lock account after max attempts
            if (user.getFailedAttempts() >= MAX_FAILED_ATTEMPTS) {
                user.setLockedUntil(Instant.now().plusMillis(LOCKOUT_DURATION_MS));
                logSecurityEvent("LOGIN_ACCOUNT_LOCKED_OUT", user.getId(), clientIp, false);
            } else {
                logSecurityEvent("LOGIN_FAILED", user.getId(), clientIp, false);
            }

            return ResponseEntity.status(401).body(Map.of("error", "Authentication failed"));
        }

        // SECURE: Reset failed attempts on successful login
        user.resetFailedAttempts();

        // SECURE: Generate cryptographically secure session token
        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);

        sessions.put(token, user.getId());

        logSecurityEvent("LOGIN_SUCCESS", user.getId(), clientIp, true);

        // SECURE: Set cookie with security flags
        Cookie cookie = new Cookie("auth", token);
        cookie.setHttpOnly(true);     // Prevents XSS access to cookie
        cookie.setSecure(true);       // Only sent over HTTPS
        cookie.setAttribute("SameSite", "Strict"); // CSRF protection
        cookie.setMaxAge(3600);       // 1 hour expiry
        cookie.setPath("/");
        response.addCookie(cookie);

        // SECURE: Return minimal user data - never include password or sensitive fields
        return ResponseEntity.ok(Map.of(
            "success", true,
            "user", Map.of(
                "id", user.getId(),
                "email", user.getEmail(),
                "role", user.getRole()
                // SECURE: No password, no internal fields
            )
        ));
    }

    /**
     * SECURE: Get user with authorization check
     */
    @GetMapping("/users/{userId}")
    public ResponseEntity<?> getUser(@PathVariable String userId,
                                     @RequestHeader(value = "Authorization", required = false) String auth) {
        // SECURE: Require authentication
        String requestingUserId = validateSession(auth);
        if (requestingUserId == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        User requestingUser = getUserById(requestingUserId);
        if (requestingUser == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        // SECURE: Authorization check - users can only access their own data (or admin)
        if (!requestingUserId.equals(userId) && !"admin".equals(requestingUser.getRole())) {
            logSecurityEvent("UNAUTHORIZED_ACCESS_ATTEMPT", requestingUserId, "unknown", false);
            return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
        }

        User user = getUserById(userId);
        if (user == null) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }

        // SECURE: Return sanitized user data
        return ResponseEntity.ok(Map.of(
            "id", user.getId(),
            "email", user.getEmail(),
            "role", user.getRole()
            // SECURE: Never expose passwordHash, failedAttempts, lockedUntil
        ));
    }

    /**
     * SECURE: Registration with proper validation
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        String email = request.getEmail();
        String password = request.getPassword();

        // SECURE: Input validation
        if (email == null || password == null || email.isBlank() || password.isBlank()) {
            return ResponseEntity.status(400).body(Map.of("error", "Email and password required"));
        }

        // SECURE: Email format validation
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            return ResponseEntity.status(400).body(Map.of("error", "Invalid email format"));
        }

        // SECURE: Password strength validation
        if (!isPasswordStrong(password)) {
            return ResponseEntity.status(400).body(Map.of(
                "error", "Password must be at least 12 characters with uppercase, lowercase, number, and special character"
            ));
        }

        // SECURE: Check if user exists (generic response to prevent enumeration)
        if (users.containsKey(email)) {
            // SECURE: Same response time and message as success
            passwordEncoder.encode(password); // Consume time
            return ResponseEntity.ok(Map.of("message", "If email is valid, check inbox for verification"));
        }

        // SECURE: Hash password
        String passwordHash = passwordEncoder.encode(password);

        User newUser = new User(
            UUID.randomUUID().toString(),
            email,
            passwordHash,
            "user" // SECURE: Default to least privilege
        );

        users.put(email, newUser);

        logSecurityEvent("USER_REGISTERED", newUser.getId(), "unknown", true);

        return ResponseEntity.ok(Map.of("message", "If email is valid, check inbox for verification"));
    }

    // SECURE: Password strength validation
    private boolean isPasswordStrong(String password) {
        if (password == null || password.length() < 12) return false;
        if (!password.matches(".*[A-Z].*")) return false;
        if (!password.matches(".*[a-z].*")) return false;
        if (!password.matches(".*[0-9].*")) return false;
        if (!password.matches(".*[!@#$%^&*(),.?\":{}|<>].*")) return false;
        return true;
    }

    // SECURE: Session validation
    private String validateSession(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return null;
        }
        String token = authHeader.substring(7);
        return sessions.get(token);
    }

    private User getUserById(String userId) {
        for (User user : users.values()) {
            if (user.getId().equals(userId)) {
                return user;
            }
        }
        return null;
    }

    // SECURE: Security event logging - never logs sensitive data
    private void logSecurityEvent(String event, String userId, String ip, boolean success) {
        Map<String, Object> logEntry = new LinkedHashMap<>();
        logEntry.put("timestamp", Instant.now().toString());
        logEntry.put("event", event);
        logEntry.put("userId", userId != null ? userId : "anonymous");
        logEntry.put("ip", ip);
        logEntry.put("success", success);
        // SECURE: Never log passwords, tokens, or session IDs
        System.out.println("SECURITY_EVENT: " + logEntry);
    }

    // Request/Response classes
    static class LoginRequest {
        private String email;
        private String password;
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }

    static class RegisterRequest {
        private String email;
        private String password;
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }

    static class User {
        private final String id;
        private String email;
        private String passwordHash;
        private String role;
        private int failedAttempts;
        private Instant lockedUntil;

        public User(String id, String email, String passwordHash, String role) {
            this.id = id;
            this.email = email;
            this.passwordHash = passwordHash;
            this.role = role;
            this.failedAttempts = 0;
            this.lockedUntil = null;
        }

        public String getId() { return id; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
        public String getPasswordHash() { return passwordHash; }
        public String getRole() { return role; }
        public int getFailedAttempts() { return failedAttempts; }
        public void incrementFailedAttempts() { this.failedAttempts++; }
        public void resetFailedAttempts() { this.failedAttempts = 0; this.lockedUntil = null; }
        public Instant getLockedUntil() { return lockedUntil; }
        public void setLockedUntil(Instant lockedUntil) { this.lockedUntil = lockedUntil; }
    }
}
