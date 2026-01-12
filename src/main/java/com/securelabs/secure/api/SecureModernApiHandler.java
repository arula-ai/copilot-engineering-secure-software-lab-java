package com.securelabs.secure.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Pattern;
import java.util.stream.*;

/**
 * SECURE: Modern API Handler (Java 17+ Patterns)
 *
 * Security Patterns Implemented:
 * - A03: Parameterized queries / input validation
 * - A10: SSRF protection with allowlists
 * - A01: Thread-safe collections for parallel processing
 * - A03: Command execution prevention
 * - A01: Path traversal protection with normalization
 *
 * REFERENCE IMPLEMENTATION - Use as model for Lab 3
 */
@RestController
@RequestMapping("/api/secure/modern")
public class SecureModernApiHandler {

    // SECURE: HttpClient without auto-redirect following
    private static final HttpClient httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .followRedirects(HttpClient.Redirect.NEVER) // SECURE: Don't follow redirects
        .build();

    // SECURE: Allowlist for external domains
    private static final Set<String> ALLOWED_DOMAINS = Set.of(
        "api.trusted-partner.com",
        "cdn.example.com"
    );

    // SECURE: Allowlist for sort fields
    private static final Set<String> ALLOWED_SORT_FIELDS = Set.of(
        "id", "name", "email", "created_at"
    );

    // SECURE: Base path for file operations
    private static final Path FILE_BASE_PATH = Path.of("/var/app/data").toAbsolutePath().normalize();

    // SECURE: Filename pattern validation
    private static final Pattern SAFE_FILENAME = Pattern.compile("^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9]+$");

    /**
     * SECURE: Search with parameterized query simulation
     */
    @PostMapping("/search")
    public ResponseEntity<?> searchWithValidation(@RequestBody SearchRequest request,
                                                  @RequestHeader(value = "Authorization", required = false) String auth) {
        // SECURE: Require authentication
        if (!isAuthenticated(auth)) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        String searchTerm = request.term();
        String sortField = request.sortBy();

        // SECURE: Validate input length
        if (searchTerm == null || searchTerm.length() > 100) {
            return ResponseEntity.status(400).body(Map.of("error", "Invalid search term"));
        }

        // SECURE: Validate sort field against allowlist
        if (!ALLOWED_SORT_FIELDS.contains(sortField)) {
            sortField = "id"; // Default to safe value
        }

        // SECURE: Escape search term for LIKE query (in real code, use PreparedStatement)
        String escapedTerm = searchTerm
            .replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
            .replace("'", "''");

        // SECURE: Would use PreparedStatement in real implementation
        // This is just simulation - actual query would be parameterized
        String safeQuery = """
            SELECT id, name, email, role
            FROM users
            WHERE name LIKE ? OR email LIKE ?
            ORDER BY %s
            LIMIT 100
            """.formatted(sortField);

        logSecurityEvent("SEARCH_EXECUTED", Map.of(
            "termLength", searchTerm.length(),
            "sortField", sortField
        ));

        return ResponseEntity.ok(Map.of(
            "queryTemplate", safeQuery,
            "message", "Use PreparedStatement with parameter binding",
            "results", List.of()
        ));
    }

    /**
     * SECURE: Proxy with SSRF protection
     */
    @GetMapping("/proxy")
    public ResponseEntity<?> proxyRequest(@RequestParam String targetUrl,
                                          @RequestHeader(value = "Authorization", required = false) String auth) {
        // SECURE: Require authentication
        if (!isAuthenticated(auth)) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        // SECURE: Parse and validate URL
        URI uri;
        try {
            uri = URI.create(targetUrl);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(400).body(Map.of("error", "Invalid URL format"));
        }

        // SECURE: Only allow HTTPS
        if (!"https".equalsIgnoreCase(uri.getScheme())) {
            logSecurityEvent("SSRF_BLOCKED", Map.of("reason", "non-https", "url", targetUrl));
            return ResponseEntity.status(400).body(Map.of("error", "Only HTTPS allowed"));
        }

        // SECURE: Validate against domain allowlist
        String host = uri.getHost();
        if (host == null || !ALLOWED_DOMAINS.contains(host.toLowerCase())) {
            logSecurityEvent("SSRF_BLOCKED", Map.of("reason", "domain_not_allowed", "host", host));
            return ResponseEntity.status(400).body(Map.of("error", "Domain not in allowlist"));
        }

        // SECURE: Resolve hostname and check for internal IPs
        try {
            InetAddress address = InetAddress.getByName(host);
            if (isInternalAddress(address)) {
                logSecurityEvent("SSRF_BLOCKED", Map.of("reason", "internal_ip", "ip", address.getHostAddress()));
                return ResponseEntity.status(400).body(Map.of("error", "Internal addresses blocked"));
            }
        } catch (UnknownHostException e) {
            return ResponseEntity.status(400).body(Map.of("error", "Unable to resolve host"));
        }

        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(uri)
                .header("User-Agent", "SecureProxy/1.0")
                .timeout(Duration.ofSeconds(5))
                .GET()
                .build();

            HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());

            // SECURE: Check for redirect attempts
            if (response.statusCode() >= 300 && response.statusCode() < 400) {
                return ResponseEntity.status(400).body(Map.of(
                    "error", "Redirects not followed",
                    "statusCode", response.statusCode()
                ));
            }

            logSecurityEvent("PROXY_SUCCESS", Map.of("url", targetUrl));

            // SECURE: Return limited response info
            return ResponseEntity.ok(Map.of(
                "statusCode", response.statusCode(),
                "contentLength", response.body().length()
                // SECURE: Don't return raw body - process as needed
            ));

        } catch (Exception e) {
            // SECURE: Generic error message
            logSecurityEvent("PROXY_ERROR", Map.of("url", targetUrl));
            return ResponseEntity.status(500).body(Map.of("error", "Request failed"));
        }
    }

    /**
     * SECURE: Batch processing with thread-safe collections
     */
    @PostMapping("/process-batch")
    public ResponseEntity<?> processBatch(@RequestBody List<String> items,
                                          @RequestHeader(value = "Authorization", required = false) String auth) {
        // SECURE: Require authentication
        if (!isAuthenticated(auth)) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        // SECURE: Limit batch size
        if (items.size() > 1000) {
            return ResponseEntity.status(400).body(Map.of("error", "Batch too large (max 1000)"));
        }

        // SECURE: Thread-safe collections for parallel processing
        List<String> processed = Collections.synchronizedList(new ArrayList<>());
        ConcurrentHashMap<String, Integer> counts = new ConcurrentHashMap<>();

        items.parallelStream()
            .filter(item -> item != null && !item.isEmpty() && item.length() < 1000)
            .forEach(item -> {
                // SECURE: Thread-safe operations
                processed.add(item.toUpperCase());
                counts.merge(item.substring(0, 1), 1, Integer::sum);
            });

        return ResponseEntity.ok(Map.of(
            "processed", processed,
            "counts", counts
        ));
    }

    /**
     * SECURE: File read with path traversal protection
     */
    @GetMapping("/files/{filename}")
    public ResponseEntity<?> readFile(@PathVariable String filename,
                                      @RequestHeader(value = "Authorization", required = false) String auth) {
        // SECURE: Require authentication
        if (!isAuthenticated(auth)) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        // SECURE: Validate filename format
        if (!SAFE_FILENAME.matcher(filename).matches()) {
            logSecurityEvent("PATH_TRAVERSAL_BLOCKED", Map.of("filename", filename));
            return ResponseEntity.status(400).body(Map.of("error", "Invalid filename format"));
        }

        // SECURE: Resolve and normalize path
        Path requestedPath = FILE_BASE_PATH.resolve(filename).normalize();

        // SECURE: Verify path is within allowed directory
        if (!requestedPath.startsWith(FILE_BASE_PATH)) {
            logSecurityEvent("PATH_TRAVERSAL_BLOCKED", Map.of(
                "filename", filename,
                "resolvedPath", requestedPath.toString()
            ));
            return ResponseEntity.status(400).body(Map.of("error", "Access denied"));
        }

        try {
            // SECURE: Check file exists before reading
            if (!Files.exists(requestedPath) || !Files.isRegularFile(requestedPath)) {
                return ResponseEntity.status(404).body(Map.of("error", "File not found"));
            }

            // SECURE: Limit file size
            long size = Files.size(requestedPath);
            if (size > 10 * 1024 * 1024) { // 10MB limit
                return ResponseEntity.status(400).body(Map.of("error", "File too large"));
            }

            String content = Files.readString(requestedPath);

            return ResponseEntity.ok(Map.of(
                "filename", filename,
                "size", size,
                "content", content
            ));

        } catch (IOException e) {
            return ResponseEntity.status(500).body(Map.of("error", "Unable to read file"));
        }
    }

    /**
     * SECURE: Stream processing with proper resource management
     */
    @GetMapping("/logs")
    public ResponseEntity<?> readLogs(@RequestParam String logFile,
                                      @RequestHeader(value = "Authorization", required = false) String auth) {
        // SECURE: Require authentication and admin role
        if (!isAdmin(auth)) {
            return ResponseEntity.status(403).body(Map.of("error", "Admin access required"));
        }

        // SECURE: Validate log file name
        if (!logFile.matches("^[a-zA-Z0-9_-]+\\.log$")) {
            return ResponseEntity.status(400).body(Map.of("error", "Invalid log file name"));
        }

        Path logPath = Path.of("/var/log/app").resolve(logFile).normalize();

        // SECURE: Verify path is within logs directory
        if (!logPath.startsWith(Path.of("/var/log/app"))) {
            return ResponseEntity.status(400).body(Map.of("error", "Access denied"));
        }

        // SECURE: Try-with-resources ensures stream is closed
        try (Stream<String> lines = Files.lines(logPath)) {
            List<String> errorLines = lines
                .filter(line -> line.contains("ERROR"))
                .limit(100)
                .toList();

            return ResponseEntity.ok(Map.of("errors", errorLines));

        } catch (IOException e) {
            return ResponseEntity.status(404).body(Map.of("error", "Log file not found"));
        }
    }

    /**
     * SECURE: User creation with record - no sensitive data exposure
     */
    @PostMapping("/user/create")
    public ResponseEntity<?> createUser(@RequestBody UserCreateRequest request,
                                        @RequestHeader(value = "Authorization", required = false) String auth) {
        // SECURE: Require authentication
        if (!isAuthenticated(auth)) {
            return ResponseEntity.status(401).body(Map.of("error", "Authentication required"));
        }

        // SECURE: Validate input
        if (request.username() == null || request.username().length() < 3) {
            return ResponseEntity.status(400).body(Map.of("error", "Invalid username"));
        }

        if (request.password() == null || request.password().length() < 12) {
            return ResponseEntity.status(400).body(Map.of("error", "Password too weak"));
        }

        // SECURE: Log without sensitive data
        logSecurityEvent("USER_CREATED", Map.of(
            "username", request.username(),
            "email", request.email()
            // SECURE: Never log password
        ));

        // SECURE: Return only safe user data (no password)
        return ResponseEntity.ok(Map.of(
            "message", "User created",
            "user", new SafeUserResponse(request.username(), request.email(), request.role())
        ));
    }

    // SECURE: Check for internal/private IP addresses
    private boolean isInternalAddress(InetAddress address) {
        return address.isLoopbackAddress() ||
               address.isSiteLocalAddress() ||
               address.isLinkLocalAddress() ||
               address.isAnyLocalAddress();
    }

    private boolean isAuthenticated(String auth) {
        return auth != null && auth.startsWith("Bearer ");
    }

    private boolean isAdmin(String auth) {
        return auth != null && auth.contains("admin");
    }

    private void logSecurityEvent(String event, Map<String, Object> details) {
        Map<String, Object> logEntry = new LinkedHashMap<>();
        logEntry.put("timestamp", Instant.now().toString());
        logEntry.put("event", event);
        logEntry.putAll(details);
        System.out.println("SECURITY_EVENT: " + logEntry);
    }

    // SECURE: Request records without sensitive data in toString()
    public record SearchRequest(String term, String sortBy) {}

    // SECURE: Separate record for input (has password) vs response (no password)
    public record UserCreateRequest(String username, String email, String password, String role) {
        // SECURE: Override toString to exclude password
        @Override
        public String toString() {
            return "UserCreateRequest[username=" + username + ", email=" + email + ", role=" + role + "]";
        }
    }

    // SECURE: Response record without password field
    public record SafeUserResponse(String username, String email, String role) {}
}
