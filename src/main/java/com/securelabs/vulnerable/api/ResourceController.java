package com.securelabs.vulnerable.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.*;
import java.util.*;

/**
 * VULNERABLE: Resource Controller
 *
 * This file contains INTENTIONAL security vulnerabilities for training purposes.
 * DO NOT use these patterns in production code.
 *
 * Vulnerabilities:
 * - A10: Server-Side Request Forgery (SSRF)
 * - A01: Broken Access Control (missing auth, IDOR)
 * - A05: Security Misconfiguration (CORS wildcard)
 * - Open Redirect vulnerability
 */
@RestController
@RequestMapping("/api/resources")
@CrossOrigin(origins = "*", allowCredentials = "true") // VULNERABLE: Wildcard CORS with credentials
public class ResourceController {

    private static final Map<String, Resource> resources = new HashMap<>();

    static {
        resources.put("res-1", new Resource("res-1", "user-1", "Resource 1 data"));
        resources.put("res-2", new Resource("res-2", "user-2", "Resource 2 data"));
    }

    /**
     * VULNERABLE: Get resource without authorization check (IDOR)
     */
    @GetMapping("/{resourceId}")
    public ResponseEntity<?> getResource(@PathVariable String resourceId) {
        // VULNERABLE: No authentication check
        // VULNERABLE: No authorization check - anyone can access any resource

        Resource resource = resources.get(resourceId);

        if (resource == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Resource not found"));
        }

        return ResponseEntity.ok(Map.of(
            "id", resource.getId(),
            "ownerId", resource.getOwnerId(),
            "data", resource.getData()
        ));
    }

    /**
     * VULNERABLE: SSRF - fetches arbitrary URLs
     */
    @GetMapping("/fetch")
    public ResponseEntity<?> fetchExternalResource(@RequestParam String url) {
        // VULNERABLE: No URL validation
        // VULNERABLE: Allows access to internal network
        // VULNERABLE: No protocol restriction

        System.out.println("Fetching URL: " + url);

        try {
            URL targetUrl = new URL(url);

            // VULNERABLE: No check for internal IP addresses (169.254.x.x, 10.x.x.x, etc.)
            // VULNERABLE: Follows redirects to internal resources
            HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            connection.setInstanceFollowRedirects(true); // VULNERABLE: Follows redirects

            int responseCode = connection.getResponseCode();

            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(connection.getInputStream()))) {
                StringBuilder response = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }

                return ResponseEntity.ok(Map.of(
                    "url", url,
                    "statusCode", responseCode,
                    "content", response.toString()
                ));
            }

        } catch (Exception e) {
            // VULNERABLE: Exposing internal error details
            return ResponseEntity.status(500).body(Map.of(
                "error", "Failed to fetch URL",
                "details", e.getMessage(),
                "stackTrace", Arrays.toString(e.getStackTrace())
            ));
        }
    }

    /**
     * VULNERABLE: SSRF via POST body
     */
    @PostMapping("/proxy")
    public ResponseEntity<?> proxyRequest(@RequestBody Map<String, String> request) {
        String targetUrl = request.get("url");
        String method = request.getOrDefault("method", "GET");

        // VULNERABLE: Same SSRF issues as above
        // Plus: allows arbitrary HTTP methods

        try {
            URL url = new URL(targetUrl);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod(method);

            // VULNERABLE: Passes through all headers
            if (request.containsKey("headers")) {
                // Could inject arbitrary headers
            }

            int responseCode = connection.getResponseCode();
            return ResponseEntity.ok(Map.of("statusCode", responseCode));

        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * VULNERABLE: Open Redirect
     */
    @GetMapping("/redirect")
    public void handleRedirect(@RequestParam String returnUrl, HttpServletResponse response) throws IOException {
        // VULNERABLE: No validation of redirect URL
        // Allows redirecting to malicious sites

        System.out.println("Redirecting to: " + returnUrl);

        // VULNERABLE: Direct redirect without validation
        response.sendRedirect(returnUrl);
    }

    /**
     * VULNERABLE: Update resource permissions without proper checks
     */
    @PutMapping("/{resourceId}/permissions")
    public ResponseEntity<?> updatePermissions(@PathVariable String resourceId,
                                               @RequestBody Map<String, Object> permissions) {
        // VULNERABLE: No authentication
        // VULNERABLE: No authorization - anyone can change any resource's permissions

        Resource resource = resources.get(resourceId);
        if (resource == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Resource not found"));
        }

        // VULNERABLE: Accepts and applies arbitrary permissions
        resource.setPermissions(permissions);

        return ResponseEntity.ok(Map.of("message", "Permissions updated"));
    }

    /**
     * VULNERABLE: Debug endpoint exposing internal state
     */
    @GetMapping("/debug")
    public ResponseEntity<?> debugInfo(HttpServletRequest request) {
        // VULNERABLE: Debug endpoint accessible in production
        // VULNERABLE: Exposes sensitive configuration

        Map<String, Object> debug = new HashMap<>();
        debug.put("resources", resources);
        debug.put("environment", System.getenv()); // VULNERABLE: Exposes env vars
        debug.put("properties", System.getProperties()); // VULNERABLE: Exposes system props
        debug.put("clientIp", request.getRemoteAddr());
        debug.put("headers", Collections.list(request.getHeaderNames()));

        return ResponseEntity.ok(debug);
    }

    /**
     * VULNERABLE: Delete without authorization
     */
    @DeleteMapping("/{resourceId}")
    public ResponseEntity<?> deleteResource(@PathVariable String resourceId) {
        // VULNERABLE: No authentication or authorization

        Resource removed = resources.remove(resourceId);

        if (removed == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Resource not found"));
        }

        return ResponseEntity.ok(Map.of("deleted", true));
    }

    /**
     * VULNERABLE: File inclusion via URL parameter
     */
    @GetMapping("/include")
    public ResponseEntity<?> includeFile(@RequestParam String file) {
        // VULNERABLE: Local/Remote file inclusion
        try {
            if (file.startsWith("http")) {
                // VULNERABLE: Remote file inclusion
                URL url = new URL(file);
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()))) {
                    StringBuilder content = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        content.append(line).append("\n");
                    }
                    return ResponseEntity.ok(Map.of("content", content.toString()));
                }
            } else {
                // VULNERABLE: Local file inclusion with path traversal
                return ResponseEntity.ok(Map.of("content",
                    new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(file)))));
            }
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }

    // Resource class
    static class Resource {
        private String id;
        private String ownerId;
        private String data;
        private Map<String, Object> permissions;

        public Resource(String id, String ownerId, String data) {
            this.id = id;
            this.ownerId = ownerId;
            this.data = data;
            this.permissions = new HashMap<>();
        }

        public String getId() { return id; }
        public String getOwnerId() { return ownerId; }
        public String getData() { return data; }
        public Map<String, Object> getPermissions() { return permissions; }
        public void setPermissions(Map<String, Object> permissions) { this.permissions = permissions; }
    }
}
