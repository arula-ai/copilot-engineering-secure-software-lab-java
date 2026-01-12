package com.securelabs.secure.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletResponse;
import java.io.*;
import java.net.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * SECURE: Resource Controller
 *
 * Security Patterns Implemented:
 * - A10: SSRF protection with URL allowlist and internal IP blocking
 * - A01: Proper authorization checks on all endpoints
 * - A05: Secure CORS configuration (specific origins)
 * - Open redirect protection with URL validation
 *
 * REFERENCE IMPLEMENTATION - Use as model for Lab 3
 */
@RestController
@RequestMapping("/api/secure/resources")
@CrossOrigin(origins = {"https://example.com", "https://app.example.com"}) // SECURE: Specific origins
public class SecureResourceController {

    private static final Map<String, Resource> resources = new ConcurrentHashMap<>();

    // SECURE: Allowlisted domains for external fetches
    private static final Set<String> ALLOWED_DOMAINS = Set.of(
        "api.example.com",
        "cdn.example.com",
        "assets.example.com"
    );

    // SECURE: Allowlisted redirect domains
    private static final Set<String> ALLOWED_REDIRECT_DOMAINS = Set.of(
        "example.com",
        "app.example.com"
    );

    // SECURE: Blocked internal IP ranges
    private static final String[] BLOCKED_IP_PREFIXES = {
        "10.",
        "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.",
        "172.24.", "172.25.", "172.26.", "172.27.",
        "172.28.", "172.29.", "172.30.", "172.31.",
        "192.168.",
        "169.254.",
        "127.",
        "0.",
        "localhost"
    };

    static {
        resources.put("res-1", new Resource("res-1", "user-1", "Resource 1 data"));
        resources.put("res-2", new Resource("res-2", "user-2", "Resource 2 data"));
    }

    /**
     * SECURE: Get resource with authorization check
     */
    @GetMapping("/{resourceId}")
    public ResponseEntity<?> getResource(@PathVariable String resourceId,
                                         @RequestHeader(value = "Authorization", required = false) String auth) {
        // SECURE: Require authentication
        String userId = validateAuth(auth);
        if (userId == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        Resource resource = resources.get(resourceId);

        if (resource == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Resource not found"));
        }

        // SECURE: Authorization check - verify user owns resource or is admin
        if (!resource.getOwnerId().equals(userId) && !isAdmin(userId)) {
            logSecurityEvent("UNAUTHORIZED_RESOURCE_ACCESS", userId, Map.of(
                "resourceId", resourceId,
                "resourceOwner", resource.getOwnerId()
            ));
            return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
        }

        return ResponseEntity.ok(Map.of(
            "id", resource.getId(),
            "ownerId", resource.getOwnerId(),
            "data", resource.getData()
        ));
    }

    /**
     * SECURE: Fetch external resource with SSRF protection
     */
    @GetMapping("/fetch")
    public ResponseEntity<?> fetchExternalResource(@RequestParam String url,
                                                   @RequestHeader(value = "Authorization", required = false) String auth) {
        // SECURE: Require authentication
        String userId = validateAuth(auth);
        if (userId == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        // SECURE: Validate URL format
        URL targetUrl;
        try {
            targetUrl = new URL(url);
        } catch (MalformedURLException e) {
            return ResponseEntity.status(400).body(Map.of("error", "Invalid URL format"));
        }

        // SECURE: Only allow HTTPS
        if (!"https".equalsIgnoreCase(targetUrl.getProtocol())) {
            logSecurityEvent("SSRF_BLOCKED_PROTOCOL", userId, Map.of("url", url, "protocol", targetUrl.getProtocol()));
            return ResponseEntity.status(400).body(Map.of("error", "Only HTTPS URLs are allowed"));
        }

        // SECURE: Check against domain allowlist
        String host = targetUrl.getHost().toLowerCase();
        if (!ALLOWED_DOMAINS.contains(host)) {
            logSecurityEvent("SSRF_BLOCKED_DOMAIN", userId, Map.of("url", url, "host", host));
            return ResponseEntity.status(400).body(Map.of("error", "Domain not in allowlist"));
        }

        // SECURE: Block internal IP addresses
        try {
            InetAddress address = InetAddress.getByName(host);
            String ip = address.getHostAddress();

            if (isInternalIp(ip) || address.isLoopbackAddress() || address.isSiteLocalAddress()) {
                logSecurityEvent("SSRF_BLOCKED_INTERNAL_IP", userId, Map.of("url", url, "resolvedIp", ip));
                return ResponseEntity.status(400).body(Map.of("error", "Internal addresses not allowed"));
            }
        } catch (UnknownHostException e) {
            return ResponseEntity.status(400).body(Map.of("error", "Unable to resolve host"));
        }

        try {
            HttpURLConnection connection = (HttpURLConnection) targetUrl.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000);
            connection.setReadTimeout(5000);
            connection.setInstanceFollowRedirects(false); // SECURE: Don't follow redirects

            int responseCode = connection.getResponseCode();

            // SECURE: Handle redirects manually to validate destination
            if (responseCode >= 300 && responseCode < 400) {
                String redirectUrl = connection.getHeaderField("Location");
                return ResponseEntity.status(400).body(Map.of(
                    "error", "Redirects not allowed",
                    "redirectUrl", redirectUrl != null ? redirectUrl : "unknown"
                ));
            }

            // SECURE: Limit response size
            int maxSize = 1024 * 1024; // 1MB max
            try (InputStream is = connection.getInputStream();
                 ByteArrayOutputStream baos = new ByteArrayOutputStream()) {

                byte[] buffer = new byte[4096];
                int bytesRead;
                int totalBytes = 0;

                while ((bytesRead = is.read(buffer)) != -1) {
                    totalBytes += bytesRead;
                    if (totalBytes > maxSize) {
                        return ResponseEntity.status(400).body(Map.of("error", "Response too large"));
                    }
                    baos.write(buffer, 0, bytesRead);
                }

                logSecurityEvent("EXTERNAL_FETCH_SUCCESS", userId, Map.of(
                    "url", url,
                    "responseSize", totalBytes
                ));

                return ResponseEntity.ok(Map.of(
                    "url", url,
                    "statusCode", responseCode,
                    "contentLength", totalBytes
                    // SECURE: Don't return raw content - process as needed
                ));
            }

        } catch (Exception e) {
            // SECURE: Generic error message - don't expose internal details
            logSecurityEvent("EXTERNAL_FETCH_ERROR", userId, Map.of("url", url));
            return ResponseEntity.status(500).body(Map.of("error", "Failed to fetch resource"));
        }
    }

    /**
     * SECURE: Redirect with URL validation
     */
    @GetMapping("/redirect")
    public ResponseEntity<?> handleRedirect(@RequestParam String returnUrl,
                                            @RequestHeader(value = "Authorization", required = false) String auth,
                                            HttpServletResponse response) {
        // SECURE: Require authentication
        String userId = validateAuth(auth);
        if (userId == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        // SECURE: Validate redirect URL
        if (!isValidRedirectUrl(returnUrl)) {
            logSecurityEvent("OPEN_REDIRECT_BLOCKED", userId, Map.of("returnUrl", returnUrl));
            return ResponseEntity.status(400).body(Map.of("error", "Invalid redirect URL"));
        }

        logSecurityEvent("REDIRECT_ALLOWED", userId, Map.of("returnUrl", returnUrl));

        return ResponseEntity.status(302)
            .header("Location", returnUrl)
            .build();
    }

    /**
     * SECURE: Update resource permissions with authorization
     */
    @PutMapping("/{resourceId}/permissions")
    public ResponseEntity<?> updatePermissions(@PathVariable String resourceId,
                                               @RequestBody Map<String, Object> permissions,
                                               @RequestHeader(value = "Authorization", required = false) String auth) {
        // SECURE: Require authentication
        String userId = validateAuth(auth);
        if (userId == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        Resource resource = resources.get(resourceId);
        if (resource == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Resource not found"));
        }

        // SECURE: Only owner or admin can modify permissions
        if (!resource.getOwnerId().equals(userId) && !isAdmin(userId)) {
            logSecurityEvent("UNAUTHORIZED_PERMISSION_UPDATE", userId, Map.of(
                "resourceId", resourceId,
                "resourceOwner", resource.getOwnerId()
            ));
            return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
        }

        // SECURE: Validate permission fields against allowlist
        Set<String> allowedFields = Set.of("read", "write", "delete", "share");
        Map<String, Object> validatedPermissions = new HashMap<>();

        for (Map.Entry<String, Object> entry : permissions.entrySet()) {
            if (allowedFields.contains(entry.getKey())) {
                // SECURE: Only allow boolean values for permissions
                if (entry.getValue() instanceof Boolean) {
                    validatedPermissions.put(entry.getKey(), entry.getValue());
                }
            }
        }

        resource.setPermissions(validatedPermissions);

        logSecurityEvent("PERMISSIONS_UPDATED", userId, Map.of(
            "resourceId", resourceId,
            "permissions", validatedPermissions
        ));

        return ResponseEntity.ok(Map.of("message", "Permissions updated"));
    }

    /**
     * SECURE: Delete resource with authorization
     */
    @DeleteMapping("/{resourceId}")
    public ResponseEntity<?> deleteResource(@PathVariable String resourceId,
                                            @RequestHeader(value = "Authorization", required = false) String auth) {
        // SECURE: Require authentication
        String userId = validateAuth(auth);
        if (userId == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        Resource resource = resources.get(resourceId);
        if (resource == null) {
            return ResponseEntity.status(404).body(Map.of("error", "Resource not found"));
        }

        // SECURE: Only owner or admin can delete
        if (!resource.getOwnerId().equals(userId) && !isAdmin(userId)) {
            logSecurityEvent("UNAUTHORIZED_DELETE_ATTEMPT", userId, Map.of(
                "resourceId", resourceId,
                "resourceOwner", resource.getOwnerId()
            ));
            return ResponseEntity.status(403).body(Map.of("error", "Access denied"));
        }

        resources.remove(resourceId);

        logSecurityEvent("RESOURCE_DELETED", userId, Map.of("resourceId", resourceId));

        return ResponseEntity.ok(Map.of("deleted", true));
    }

    // SECURE: Check if IP is in internal/private range
    private boolean isInternalIp(String ip) {
        for (String prefix : BLOCKED_IP_PREFIXES) {
            if (ip.startsWith(prefix)) {
                return true;
            }
        }
        return false;
    }

    // SECURE: Validate redirect URL against allowlist
    private boolean isValidRedirectUrl(String urlString) {
        // SECURE: Allow relative URLs starting with /
        if (urlString.startsWith("/") && !urlString.startsWith("//")) {
            return true;
        }

        try {
            URL url = new URL(urlString);

            // SECURE: Only allow HTTPS
            if (!"https".equalsIgnoreCase(url.getProtocol())) {
                return false;
            }

            // SECURE: Check domain against allowlist
            String host = url.getHost().toLowerCase();
            for (String allowedDomain : ALLOWED_REDIRECT_DOMAINS) {
                if (host.equals(allowedDomain) || host.endsWith("." + allowedDomain)) {
                    return true;
                }
            }

            return false;
        } catch (MalformedURLException e) {
            return false;
        }
    }

    private String validateAuth(String auth) {
        if (auth != null && auth.startsWith("Bearer ")) {
            return "user-" + auth.substring(7, Math.min(17, auth.length()));
        }
        return null;
    }

    private boolean isAdmin(String userId) {
        return userId != null && userId.contains("admin");
    }

    private void logSecurityEvent(String event, String userId, Map<String, Object> details) {
        Map<String, Object> logEntry = new LinkedHashMap<>();
        logEntry.put("timestamp", Instant.now().toString());
        logEntry.put("event", event);
        logEntry.put("userId", userId != null ? userId : "anonymous");
        logEntry.putAll(details);
        System.out.println("SECURITY_EVENT: " + logEntry);
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
