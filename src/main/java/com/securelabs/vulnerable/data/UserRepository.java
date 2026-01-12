package com.securelabs.vulnerable.data;

import java.io.*;
import java.nio.file.*;
import java.sql.*;
import java.util.*;

/**
 * VULNERABLE: User Repository
 *
 * This file contains INTENTIONAL security vulnerabilities for training purposes.
 * DO NOT use these patterns in production code.
 *
 * Vulnerabilities:
 * - A03: SQL Injection in multiple methods
 * - A03: Command Injection in exportUsers
 * - A01: Path Traversal in file operations
 */
public class UserRepository {

    private Connection connection;

    public UserRepository(Connection connection) {
        this.connection = connection;
    }

    /**
     * VULNERABLE: SQL Injection via string concatenation
     */
    public Map<String, Object> findByEmail(String email) throws SQLException {
        // VULNERABLE: Direct string concatenation enables SQL injection
        String query = "SELECT * FROM users WHERE email = '" + email + "'";

        System.out.println("Executing query: " + query);

        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);

        if (rs.next()) {
            Map<String, Object> user = new HashMap<>();
            user.put("id", rs.getString("id"));
            user.put("email", rs.getString("email"));
            user.put("password_hash", rs.getString("password_hash"));
            user.put("role", rs.getString("role"));
            return user;
        }

        return null;
    }

    /**
     * VULNERABLE: SQL Injection in search with LIKE
     */
    public List<Map<String, Object>> searchUsers(String searchTerm, String orderBy) throws SQLException {
        // VULNERABLE: Both searchTerm and orderBy are injectable
        String query = "SELECT * FROM users WHERE email LIKE '%" + searchTerm + "%' ORDER BY " + orderBy;

        System.out.println("Executing search query: " + query);

        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);

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

    /**
     * VULNERABLE: SQL Injection with dynamic field selection
     */
    public List<Map<String, Object>> findByQuery(String field, String value) throws SQLException {
        // VULNERABLE: Field name is user-controlled - allows accessing any column
        String query = "SELECT * FROM users WHERE " + field + " = '" + value + "'";

        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);

        List<Map<String, Object>> results = new ArrayList<>();
        while (rs.next()) {
            Map<String, Object> user = new HashMap<>();
            user.put("id", rs.getString("id"));
            user.put("email", rs.getString("email"));
            results.add(user);
        }

        return results;
    }

    /**
     * VULNERABLE: SQL Injection in INSERT statement
     */
    public void createUser(String email, String passwordHash, String role) throws SQLException {
        // VULNERABLE: SQL injection in INSERT
        String query = "INSERT INTO users (email, password_hash, role) VALUES ('" +
                       email + "', '" + passwordHash + "', '" + role + "')";

        System.out.println("Creating user: " + query);

        Statement stmt = connection.createStatement();
        stmt.executeUpdate(query);
    }

    /**
     * VULNERABLE: SQL Injection in UPDATE statement
     */
    public void updateUser(String userId, String field, String value) throws SQLException {
        // VULNERABLE: Both field and value are injectable
        String query = "UPDATE users SET " + field + " = '" + value + "' WHERE id = '" + userId + "'";

        Statement stmt = connection.createStatement();
        stmt.executeUpdate(query);
    }

    /**
     * VULNERABLE: SQL Injection in DELETE statement
     */
    public void deleteUser(String userId) throws SQLException {
        // VULNERABLE: SQL injection via userId
        String query = "DELETE FROM users WHERE id = '" + userId + "'";

        Statement stmt = connection.createStatement();
        stmt.executeUpdate(query);
    }

    /**
     * VULNERABLE: Command Injection in export functionality
     */
    public String exportUsers(String format) throws Exception {
        String filename = "/tmp/users_export." + format;

        // VULNERABLE: Command injection via format parameter
        String command = "mysqldump -u root database_name users > " + filename;

        System.out.println("Executing export command: " + command);

        // VULNERABLE: Direct command execution with user input
        Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});

        return filename;
    }

    /**
     * VULNERABLE: Path Traversal in file operations
     */
    public byte[] getUserAvatar(String username) throws IOException {
        // VULNERABLE: Path traversal - username can contain ../
        String avatarPath = "/var/www/avatars/" + username + ".png";

        System.out.println("Reading avatar from: " + avatarPath);

        // VULNERABLE: No path validation allows reading arbitrary files
        return Files.readAllBytes(Paths.get(avatarPath));
    }

    /**
     * VULNERABLE: Path Traversal in file upload
     */
    public void saveUserAvatar(String username, byte[] data) throws IOException {
        // VULNERABLE: Path traversal allows writing to arbitrary locations
        String avatarPath = "/var/www/avatars/" + username + ".png";

        Files.write(Paths.get(avatarPath), data);
    }

    /**
     * VULNERABLE: Unsafe deserialization of user data
     */
    public Object loadUserData(byte[] serializedData) throws Exception {
        // VULNERABLE: Deserializing untrusted data
        ByteArrayInputStream bis = new ByteArrayInputStream(serializedData);
        ObjectInputStream ois = new ObjectInputStream(bis);

        // VULNERABLE: No validation of deserialized object type
        return ois.readObject();
    }

    /**
     * VULNERABLE: SQL Injection in batch operations
     */
    public void batchUpdateRoles(List<String> userIds, String newRole) throws SQLException {
        for (String userId : userIds) {
            // VULNERABLE: SQL injection in loop
            String query = "UPDATE users SET role = '" + newRole + "' WHERE id = '" + userId + "'";
            connection.createStatement().executeUpdate(query);
        }
    }
}
