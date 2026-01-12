package com.securelabs.vulnerable.auth;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * VULNERABLE: Authentication Controller
 *
 * This file contains INTENTIONAL security vulnerabilities for training purposes.
 * DO NOT use these patterns in production code.
 *
 * Vulnerabilities:
 * - A02: Weak password hashing (MD5)
 * - A07: No rate limiting, no account lockout
 * - A09: Sensitive data in logs
 * - A01: Missing authorization checks (IDOR)
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    // VULNERABLE: Simulated user store (in production, use proper database)
    private static final Map<String, User> users = new HashMap<>();
    private static final Map<String, String> sessions = new HashMap<>();

    static {
        // Demo user with MD5 password
        users.put("admin@example.com", new User("1", "admin@example.com", "5f4dcc3b5aa765d61d8327deb882cf99", "admin"));
        users.put("user@example.com", new User("2", "user@example.com", "5f4dcc3b5aa765d61d8327deb882cf99", "user"));
    }

    /**
     * VULNERABLE: Login endpoint with multiple security issues
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletResponse response) {
        String email = request.getEmail();
        String password = request.getPassword();

        // VULNERABLE: Logging password in plain text (A09)
        System.out.println("Login attempt - Email: " + email + ", Password: " + password);

        User user = users.get(email);

        // VULNERABLE: User enumeration - different messages reveal if user exists
        if (user == null) {
            return ResponseEntity.status(401).body(Map.of("error", "User not found"));
        }

        // VULNERABLE: MD5 password hashing (A02)
        String hashedPassword = md5Hash(password);

        if (!hashedPassword.equals(user.getPasswordHash())) {
            // VULNERABLE: No account lockout after failed attempts (A07)
            return ResponseEntity.status(401).body(Map.of("error", "Invalid password"));
        }

        // VULNERABLE: Weak session token generation
        String token = UUID.randomUUID().toString();
        sessions.put(token, user.getId());

        // VULNERABLE: Insecure cookie settings (A07)
        Cookie cookie = new Cookie("session", token);
        cookie.setPath("/");
        // Missing: httpOnly, secure, sameSite flags
        response.addCookie(cookie);

        // VULNERABLE: Returning sensitive data including password hash
        System.out.println("Login successful - User: " + user.getEmail() + ", Token: " + token);

        Map<String, Object> responseBody = new HashMap<>();
        responseBody.put("success", true);
        responseBody.put("user", Map.of(
            "id", user.getId(),
            "email", user.getEmail(),
            "role", user.getRole(),
            "passwordHash", user.getPasswordHash()  // VULNERABLE: Exposing password hash
        ));
        responseBody.put("token", token);

        return ResponseEntity.ok(responseBody);
    }

    /**
     * VULNERABLE: Get user endpoint with IDOR vulnerability
     */
    @GetMapping("/users/{userId}")
    public ResponseEntity<?> getUser(@PathVariable String userId, @RequestHeader(value = "Authorization", required = false) String auth) {
        // VULNERABLE: No authentication check - anyone can access any user
        // VULNERABLE: IDOR - no authorization check for resource ownership

        for (User user : users.values()) {
            if (user.getId().equals(userId)) {
                // VULNERABLE: Exposing all user data including password hash
                return ResponseEntity.ok(Map.of(
                    "id", user.getId(),
                    "email", user.getEmail(),
                    "role", user.getRole(),
                    "passwordHash", user.getPasswordHash()
                ));
            }
        }

        return ResponseEntity.status(404).body(Map.of("error", "User not found"));
    }

    /**
     * VULNERABLE: Update user with mass assignment
     */
    @PutMapping("/users/{userId}")
    public ResponseEntity<?> updateUser(@PathVariable String userId, @RequestBody Map<String, String> updates) {
        // VULNERABLE: No authentication or authorization check

        for (User user : users.values()) {
            if (user.getId().equals(userId)) {
                // VULNERABLE: Mass assignment - allows setting any field including role
                if (updates.containsKey("email")) {
                    user.setEmail(updates.get("email"));
                }
                if (updates.containsKey("role")) {
                    // VULNERABLE: Allows privilege escalation
                    user.setRole(updates.get("role"));
                }
                if (updates.containsKey("passwordHash")) {
                    // VULNERABLE: Direct password hash manipulation
                    user.setPasswordHash(updates.get("passwordHash"));
                }

                System.out.println("User updated: " + user.getEmail() + " - New role: " + user.getRole());

                return ResponseEntity.ok(Map.of("message", "User updated", "user", user));
            }
        }

        return ResponseEntity.status(404).body(Map.of("error", "User not found"));
    }

    /**
     * VULNERABLE: Registration with weak password handling
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        String email = request.getEmail();
        String password = request.getPassword();

        // VULNERABLE: Logging password (A09)
        System.out.println("Registration - Email: " + email + ", Password: " + password);

        // VULNERABLE: No password strength validation
        if (password == null || password.length() < 1) {
            return ResponseEntity.badRequest().body(Map.of("error", "Password required"));
        }

        // VULNERABLE: User enumeration through registration
        if (users.containsKey(email)) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email already registered"));
        }

        // VULNERABLE: MD5 password hashing (A02)
        String passwordHash = md5Hash(password);

        User newUser = new User(
            String.valueOf(users.size() + 1),
            email,
            passwordHash,
            "user"
        );

        users.put(email, newUser);

        return ResponseEntity.ok(Map.of(
            "message", "User registered",
            "user", Map.of("id", newUser.getId(), "email", newUser.getEmail())
        ));
    }

    /**
     * VULNERABLE: MD5 hashing - cryptographically broken
     */
    private String md5Hash(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return input; // VULNERABLE: Return plain text on error
        }
    }

    // Inner classes for request/response
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
        private String id;
        private String email;
        private String passwordHash;
        private String role;

        public User(String id, String email, String passwordHash, String role) {
            this.id = id;
            this.email = email;
            this.passwordHash = passwordHash;
            this.role = role;
        }

        public String getId() { return id; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
        public String getPasswordHash() { return passwordHash; }
        public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
        public String getRole() { return role; }
        public void setRole(String role) { this.role = role; }
    }
}
