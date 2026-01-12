package com.securelabs.secure.data;

import java.nio.file.*;
import java.sql.*;
import java.util.*;

/**
 * SECURE: User Repository
 *
 * Security Patterns Implemented:
 * - A03: Parameterized queries prevent SQL injection
 * - A01: Path traversal prevention in file operations
 * - Command injection prevention
 *
 * REFERENCE IMPLEMENTATION - Use as model for Lab 3
 */
public class SecureUserRepository {

    private Connection connection;

    // SECURE: Whitelist of allowed columns for ordering
    private static final Set<String> ALLOWED_ORDER_COLUMNS = Set.of("id", "email", "created_at");
    private static final Set<String> ALLOWED_QUERY_FIELDS = Set.of("id", "email", "role");

    // SECURE: Safe base path for file operations
    private static final Path AVATAR_BASE_PATH = Paths.get("/var/www/avatars").toAbsolutePath().normalize();

    public SecureUserRepository(Connection connection) {
        this.connection = connection;
    }

    /**
     * SECURE: Parameterized query prevents SQL injection
     */
    public Map<String, Object> findByEmail(String email) throws SQLException {
        // SECURE: Using PreparedStatement with parameter binding
        String query = "SELECT id, email, role, created_at FROM users WHERE email = ?";

        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, email);

            try (ResultSet rs = stmt.executeQuery()) {
                if (rs.next()) {
                    Map<String, Object> user = new HashMap<>();
                    user.put("id", rs.getString("id"));
                    user.put("email", rs.getString("email"));
                    user.put("role", rs.getString("role"));
                    user.put("createdAt", rs.getTimestamp("created_at"));
                    // SECURE: Never return password_hash
                    return user;
                }
            }
        }
        return null;
    }

    /**
     * SECURE: Parameterized LIKE query with validated ORDER BY
     */
    public List<Map<String, Object>> searchUsers(String searchTerm, String orderBy) throws SQLException {
        // SECURE: Validate orderBy against whitelist
        if (!ALLOWED_ORDER_COLUMNS.contains(orderBy)) {
            orderBy = "id"; // Default to safe value
        }

        // SECURE: Parameterized query - escape wildcards in search term
        String sanitizedSearch = searchTerm
            .replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_");

        // SECURE: OrderBy is validated, so safe to use in query
        String query = "SELECT id, email, role FROM users WHERE email LIKE ? ESCAPE '\\' ORDER BY " + orderBy + " LIMIT 100";

        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, "%" + sanitizedSearch + "%");

            try (ResultSet rs = stmt.executeQuery()) {
                List<Map<String, Object>> results = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> user = new HashMap<>();
                    user.put("id", rs.getString("id"));
                    user.put("email", rs.getString("email"));
                    user.put("role", rs.getString("role"));
                    results.add(user);
                }
                return results;
            }
        }
    }

    /**
     * SECURE: Parameterized query with field whitelist validation
     */
    public List<Map<String, Object>> findByQuery(String field, String value) throws SQLException {
        // SECURE: Validate field against whitelist
        if (!ALLOWED_QUERY_FIELDS.contains(field)) {
            throw new IllegalArgumentException("Invalid query field: " + field);
        }

        // SECURE: Field is validated, value is parameterized
        String query = "SELECT id, email, role FROM users WHERE " + field + " = ?";

        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, value);

            try (ResultSet rs = stmt.executeQuery()) {
                List<Map<String, Object>> results = new ArrayList<>();
                while (rs.next()) {
                    Map<String, Object> user = new HashMap<>();
                    user.put("id", rs.getString("id"));
                    user.put("email", rs.getString("email"));
                    user.put("role", rs.getString("role"));
                    results.add(user);
                }
                return results;
            }
        }
    }

    /**
     * SECURE: Parameterized INSERT
     */
    public String createUser(String email, String passwordHash, String role) throws SQLException {
        String id = UUID.randomUUID().toString();

        // SECURE: All values are parameterized
        String query = "INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)";

        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, id);
            stmt.setString(2, email);
            stmt.setString(3, passwordHash);
            stmt.setString(4, role);
            stmt.executeUpdate();
        }

        // SECURE: Log without sensitive data
        System.out.println("User created: " + id);

        return id;
    }

    /**
     * SECURE: Parameterized UPDATE with field whitelist
     */
    public void updateUser(String userId, String field, String value) throws SQLException {
        // SECURE: Validate field against whitelist (excludes password_hash, role for regular updates)
        Set<String> allowedUpdateFields = Set.of("email");
        if (!allowedUpdateFields.contains(field)) {
            throw new IllegalArgumentException("Field not allowed for update: " + field);
        }

        String query = "UPDATE users SET " + field + " = ? WHERE id = ?";

        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            stmt.setString(1, value);
            stmt.setString(2, userId);
            stmt.executeUpdate();
        }
    }

    /**
     * SECURE: Safe export using database API (no command injection)
     */
    public List<Map<String, Object>> exportUsers() throws SQLException {
        // SECURE: Use database query instead of shell command
        String query = "SELECT id, email, role, created_at FROM users";

        try (PreparedStatement stmt = connection.prepareStatement(query);
             ResultSet rs = stmt.executeQuery()) {

            List<Map<String, Object>> users = new ArrayList<>();
            while (rs.next()) {
                Map<String, Object> user = new HashMap<>();
                user.put("id", rs.getString("id"));
                user.put("email", rs.getString("email"));
                user.put("role", rs.getString("role"));
                user.put("createdAt", rs.getTimestamp("created_at"));
                // SECURE: Never export password_hash
                users.add(user);
            }
            return users;
        }
    }

    /**
     * SECURE: Path traversal prevention in file operations
     */
    public byte[] getUserAvatar(String username) throws Exception {
        // SECURE: Validate username format
        if (!username.matches("^[a-zA-Z0-9_-]+$")) {
            throw new IllegalArgumentException("Invalid username format");
        }

        // SECURE: Construct path safely and validate it's within allowed directory
        Path requestedPath = AVATAR_BASE_PATH.resolve(username + ".png").normalize();

        // SECURE: Verify path is within allowed directory
        if (!requestedPath.startsWith(AVATAR_BASE_PATH)) {
            throw new SecurityException("Path traversal attempt detected");
        }

        // SECURE: Check file exists before reading
        if (!Files.exists(requestedPath)) {
            throw new NoSuchFileException("Avatar not found");
        }

        return Files.readAllBytes(requestedPath);
    }

    /**
     * SECURE: Safe file upload with path validation
     */
    public void saveUserAvatar(String username, byte[] data) throws Exception {
        // SECURE: Validate username format
        if (!username.matches("^[a-zA-Z0-9_-]+$")) {
            throw new IllegalArgumentException("Invalid username format");
        }

        // SECURE: Validate file size
        if (data.length > 5 * 1024 * 1024) { // 5MB max
            throw new IllegalArgumentException("File too large");
        }

        // SECURE: Validate image magic bytes
        if (!isValidImage(data)) {
            throw new IllegalArgumentException("Invalid image format");
        }

        Path targetPath = AVATAR_BASE_PATH.resolve(username + ".png").normalize();

        // SECURE: Verify path is within allowed directory
        if (!targetPath.startsWith(AVATAR_BASE_PATH)) {
            throw new SecurityException("Path traversal attempt detected");
        }

        Files.write(targetPath, data);
    }

    /**
     * SECURE: Validate image magic bytes
     */
    private boolean isValidImage(byte[] data) {
        if (data.length < 8) return false;

        // PNG magic bytes
        if (data[0] == (byte) 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47) {
            return true;
        }
        // JPEG magic bytes
        if (data[0] == (byte) 0xFF && data[1] == (byte) 0xD8 && data[2] == (byte) 0xFF) {
            return true;
        }

        return false;
    }

    /**
     * SECURE: Batch operations with parameterized queries
     */
    public void batchUpdateRoles(List<String> userIds, String newRole) throws SQLException {
        // SECURE: Validate role
        Set<String> validRoles = Set.of("user", "moderator", "admin");
        if (!validRoles.contains(newRole)) {
            throw new IllegalArgumentException("Invalid role");
        }

        String query = "UPDATE users SET role = ? WHERE id = ?";

        try (PreparedStatement stmt = connection.prepareStatement(query)) {
            for (String userId : userIds) {
                // SECURE: Validate user ID format
                if (!userId.matches("^[a-zA-Z0-9-]+$")) {
                    continue;
                }
                stmt.setString(1, newRole);
                stmt.setString(2, userId);
                stmt.addBatch();
            }
            stmt.executeBatch();
        }
    }
}
