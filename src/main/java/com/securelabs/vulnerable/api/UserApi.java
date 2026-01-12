package com.securelabs.vulnerable.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

/**
 * VULNERABLE: User API
 *
 * This file contains INTENTIONAL security vulnerabilities for training purposes.
 * DO NOT use these patterns in production code.
 *
 * Vulnerabilities:
 * - A01: Missing authentication and authorization
 * - A05: Debug endpoints in production
 * - A03: No input validation
 * - A09: Information disclosure in errors
 */
@RestController
@RequestMapping("/api/users")
public class UserApi {

    private static final Map<String, User> users = new HashMap<>();

    static {
        users.put("1", new User("1", "admin@example.com", "admin", "password123"));
        users.put("2", new User("2", "user@example.com", "user", "userpass"));
    }

    /**
     * VULNERABLE: List all users without authentication
     */
    @GetMapping
    public ResponseEntity<?> listUsers() {
        // VULNERABLE: No authentication required
        // VULNERABLE: No pagination - dumps all users
        // VULNERABLE: Exposes password field

        List<Map<String, Object>> result = new ArrayList<>();
        for (User user : users.values()) {
            result.add(Map.of(
                "id", user.getId(),
                "email", user.getEmail(),
                "role", user.getRole(),
                "password", user.getPassword() // VULNERABLE: Exposing passwords
            ));
        }

        return ResponseEntity.ok(result);
    }

    /**
     * VULNERABLE: Get user by ID - IDOR vulnerability
     */
    @GetMapping("/{userId}")
    public ResponseEntity<?> getUser(@PathVariable String userId) {
        // VULNERABLE: No authentication
        // VULNERABLE: IDOR - can access any user

        User user = users.get(userId);

        if (user == null) {
            // VULNERABLE: User enumeration via different error
            return ResponseEntity.status(404).body(Map.of("error", "User " + userId + " does not exist"));
        }

        return ResponseEntity.ok(Map.of(
            "id", user.getId(),
            "email", user.getEmail(),
            "role", user.getRole(),
            "password", user.getPassword() // VULNERABLE
        ));
    }

    /**
     * VULNERABLE: Search users with injection risk
     */
    @GetMapping("/search")
    public ResponseEntity<?> searchUsers(@RequestParam String query) {
        // VULNERABLE: No input validation or sanitization
        // VULNERABLE: No authentication

        List<Map<String, Object>> results = new ArrayList<>();
        for (User user : users.values()) {
            if (user.getEmail().contains(query)) {
                results.add(Map.of(
                    "id", user.getId(),
                    "email", user.getEmail(),
                    "role", user.getRole()
                ));
            }
        }

        // VULNERABLE: No result limit
        return ResponseEntity.ok(results);
    }

    /**
     * VULNERABLE: Update user with mass assignment
     */
    @PutMapping("/{userId}")
    public ResponseEntity<?> updateUser(@PathVariable String userId, @RequestBody Map<String, Object> updates) {
        // VULNERABLE: No authentication or authorization

        User user = users.get(userId);
        if (user == null) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }

        // VULNERABLE: Mass assignment - allows setting any field
        if (updates.containsKey("email")) {
            user.setEmail((String) updates.get("email"));
        }
        if (updates.containsKey("role")) {
            // VULNERABLE: Privilege escalation via role change
            user.setRole((String) updates.get("role"));
        }
        if (updates.containsKey("password")) {
            // VULNERABLE: No password strength validation
            user.setPassword((String) updates.get("password"));
        }

        return ResponseEntity.ok(Map.of("message", "User updated", "user", Map.of(
            "id", user.getId(),
            "email", user.getEmail(),
            "role", user.getRole()
        )));
    }

    /**
     * VULNERABLE: Delete user without authorization
     */
    @DeleteMapping("/{userId}")
    public ResponseEntity<?> deleteUser(@PathVariable String userId) {
        // VULNERABLE: No authentication
        // VULNERABLE: No authorization - anyone can delete any user
        // VULNERABLE: No audit logging

        User removed = users.remove(userId);

        if (removed == null) {
            return ResponseEntity.status(404).body(Map.of("error", "User not found"));
        }

        return ResponseEntity.ok(Map.of("deleted", true, "userId", userId));
    }

    /**
     * VULNERABLE: Debug endpoint exposing sensitive data
     */
    @GetMapping("/debug/all")
    public ResponseEntity<?> debugAllUsers() {
        // VULNERABLE: Debug endpoint accessible in production
        // VULNERABLE: Exposes all user data including passwords

        return ResponseEntity.ok(Map.of(
            "users", users,
            "count", users.size(),
            "timestamp", System.currentTimeMillis()
        ));
    }

    /**
     * VULNERABLE: Admin endpoint without proper protection
     */
    @PostMapping("/admin/reset-passwords")
    public ResponseEntity<?> resetAllPasswords() {
        // VULNERABLE: No authentication
        // VULNERABLE: No admin role check
        // VULNERABLE: No audit logging

        for (User user : users.values()) {
            user.setPassword("reset123"); // VULNERABLE: Weak default password
        }

        return ResponseEntity.ok(Map.of("message", "All passwords reset to default"));
    }

    /**
     * VULNERABLE: Bulk operations without validation
     */
    @PostMapping("/bulk-create")
    public ResponseEntity<?> bulkCreateUsers(@RequestBody List<Map<String, Object>> userList) {
        // VULNERABLE: No authentication
        // VULNERABLE: No input validation
        // VULNERABLE: No rate limiting

        List<String> createdIds = new ArrayList<>();
        for (Map<String, Object> userData : userList) {
            String id = String.valueOf(users.size() + 1);
            User user = new User(
                id,
                (String) userData.get("email"),
                (String) userData.getOrDefault("role", "admin"), // VULNERABLE: Default admin role
                (String) userData.getOrDefault("password", "password")
            );
            users.put(id, user);
            createdIds.add(id);
        }

        return ResponseEntity.ok(Map.of("created", createdIds));
    }

    // User class
    static class User {
        private String id;
        private String email;
        private String role;
        private String password;

        public User(String id, String email, String role, String password) {
            this.id = id;
            this.email = email;
            this.role = role;
            this.password = password;
        }

        public String getId() { return id; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
        public String getRole() { return role; }
        public void setRole(String role) { this.role = role; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }
}
