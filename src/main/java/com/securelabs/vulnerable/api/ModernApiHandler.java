package com.securelabs.vulnerable.api;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.*;

/**
 * VULNERABLE: Modern API Handler (Java 17+ Patterns)
 *
 * This file contains INTENTIONAL security vulnerabilities using Java 17+ features.
 * DO NOT use these patterns in production code.
 *
 * Vulnerabilities:
 * - A03: SQL injection via text blocks
 * - A10: SSRF via Java 11+ HttpClient
 * - A08: Insecure deserialization with records
 * - A01: Race conditions with parallel streams
 * - A03: Command injection via ProcessBuilder
 * - A01: Path traversal with Files API
 */
@RestController
@RequestMapping("/api/modern")
public class ModernApiHandler {

    private static final HttpClient httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(10))
        .followRedirects(HttpClient.Redirect.ALWAYS) // VULNERABLE: Follows all redirects
        .build();

    /**
     * VULNERABLE: SQL injection via Java text blocks
     * Text blocks make multi-line SQL easier to write but injection is still possible
     */
    @PostMapping("/search")
    public ResponseEntity<?> searchWithTextBlock(@RequestBody SearchRequest request) {
        String searchTerm = request.term();
        String sortField = request.sortBy();

        // VULNERABLE: Text block SQL with string concatenation
        String query = """
            SELECT id, name, email, role
            FROM users
            WHERE name LIKE '%%%s%%'
            OR email LIKE '%%%s%%'
            ORDER BY %s
            LIMIT 100
            """.formatted(searchTerm, searchTerm, sortField);

        System.out.println("Executing query: " + query);

        // Simulated result
        return ResponseEntity.ok(Map.of(
            "query", query,
            "results", List.of()
        ));
    }

    /**
     * VULNERABLE: SSRF using Java 11+ HttpClient
     * Modern HttpClient API but same SSRF risks
     */
    @GetMapping("/proxy")
    public ResponseEntity<?> proxyRequest(@RequestParam String targetUrl) {
        // VULNERABLE: No URL validation
        // VULNERABLE: No internal IP blocking
        // VULNERABLE: Follows redirects automatically

        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(targetUrl))
                .header("User-Agent", "ModernApiHandler/1.0")
                .GET()
                .build();

            HttpResponse<String> response = httpClient.send(request,
                HttpResponse.BodyHandlers.ofString());

            // VULNERABLE: Returns full response including potential internal data
            return ResponseEntity.ok(Map.of(
                "statusCode", response.statusCode(),
                "headers", response.headers().map(),
                "body", response.body()
            ));

        } catch (Exception e) {
            // VULNERABLE: Exposes internal error details
            return ResponseEntity.status(500).body(Map.of(
                "error", e.getClass().getName(),
                "message", e.getMessage(),
                "cause", e.getCause() != null ? e.getCause().getMessage() : "none"
            ));
        }
    }

    /**
     * VULNERABLE: Async SSRF with CompletableFuture
     * Can be used for blind SSRF attacks
     */
    @PostMapping("/async-fetch")
    public ResponseEntity<?> asyncFetch(@RequestBody List<String> urls) {
        // VULNERABLE: Fetches multiple URLs without validation
        // VULNERABLE: Can be used for port scanning, DDOS amplification

        List<CompletableFuture<Map<String, Object>>> futures = urls.stream()
            .map(url -> CompletableFuture.supplyAsync(() -> {
                try {
                    HttpRequest request = HttpRequest.newBuilder()
                        .uri(URI.create(url))
                        .GET()
                        .build();

                    HttpResponse<String> response = httpClient.send(request,
                        HttpResponse.BodyHandlers.ofString());

                    return Map.<String, Object>of(
                        "url", url,
                        "status", response.statusCode()
                    );
                } catch (Exception e) {
                    return Map.<String, Object>of(
                        "url", url,
                        "error", e.getMessage()
                    );
                }
            }))
            .toList();

        List<Map<String, Object>> results = futures.stream()
            .map(CompletableFuture::join)
            .toList();

        return ResponseEntity.ok(results);
    }

    /**
     * VULNERABLE: Race condition with parallel stream and mutable state
     */
    @PostMapping("/process-batch")
    public ResponseEntity<?> processBatch(@RequestBody List<String> items) {
        // VULNERABLE: Shared mutable state with parallel stream
        List<String> processed = new ArrayList<>(); // Not thread-safe!
        Map<String, Integer> counts = new HashMap<>(); // Not thread-safe!

        items.parallelStream()
            .filter(item -> item != null && !item.isEmpty())
            .forEach(item -> {
                // VULNERABLE: Race condition - ArrayList is not thread-safe
                processed.add(item.toUpperCase());

                // VULNERABLE: Race condition on HashMap
                counts.merge(item.substring(0, 1), 1, Integer::sum);
            });

        return ResponseEntity.ok(Map.of(
            "processed", processed,
            "counts", counts,
            "warning", "Results may be inconsistent due to race conditions"
        ));
    }

    /**
     * VULNERABLE: Command injection via ProcessBuilder
     */
    @PostMapping("/execute")
    public ResponseEntity<?> executeCommand(@RequestBody CommandRequest request) {
        String command = request.command();
        List<String> args = request.arguments();

        // VULNERABLE: Direct command execution with user input
        try {
            List<String> fullCommand = new ArrayList<>();
            fullCommand.add(command);
            fullCommand.addAll(args);

            ProcessBuilder pb = new ProcessBuilder(fullCommand);
            pb.redirectErrorStream(true);

            Process process = pb.start();

            String output;
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                output = reader.lines().collect(Collectors.joining("\n"));
            }

            int exitCode = process.waitFor();

            // VULNERABLE: Returns command output
            return ResponseEntity.ok(Map.of(
                "command", String.join(" ", fullCommand),
                "exitCode", exitCode,
                "output", output
            ));

        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * VULNERABLE: Path traversal with modern Files API
     */
    @GetMapping("/files/{filename}")
    public ResponseEntity<?> readFile(@PathVariable String filename) {
        // VULNERABLE: Path traversal - filename can contain ../
        Path basePath = Path.of("/var/app/data");
        Path filePath = basePath.resolve(filename); // VULNERABLE: No normalization check

        try {
            // VULNERABLE: No check if resolved path is within basePath
            String content = Files.readString(filePath);

            return ResponseEntity.ok(Map.of(
                "filename", filename,
                "path", filePath.toString(),
                "content", content
            ));

        } catch (IOException e) {
            return ResponseEntity.status(404).body(Map.of("error", "File not found"));
        }
    }

    /**
     * VULNERABLE: Arbitrary file write with Files API
     */
    @PostMapping("/files/{filename}")
    public ResponseEntity<?> writeFile(@PathVariable String filename,
                                       @RequestBody String content) {
        // VULNERABLE: Path traversal in write operation
        Path basePath = Path.of("/var/app/uploads");
        Path filePath = basePath.resolve(filename);

        try {
            // VULNERABLE: Can write to arbitrary locations
            Files.writeString(filePath, content);

            return ResponseEntity.ok(Map.of(
                "message", "File written",
                "path", filePath.toString()
            ));

        } catch (IOException e) {
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * VULNERABLE: Record with sensitive data exposure
     * Records auto-generate toString() which can leak sensitive data
     */
    @PostMapping("/user/create")
    public ResponseEntity<?> createUser(@RequestBody UserRecord user) {
        // VULNERABLE: Record's toString() exposes password
        System.out.println("Creating user: " + user); // Logs password!

        // VULNERABLE: Returning entire record including password
        return ResponseEntity.ok(Map.of(
            "message", "User created",
            "user", user.toString() // Exposes password in response
        ));
    }

    /**
     * VULNERABLE: Type checking with unchecked casts
     * Java 17 pattern matching in instanceof
     */
    @PostMapping("/process")
    public ResponseEntity<?> processObject(@RequestBody Map<String, Object> data) {
        Object value = data.get("payload");

        // VULNERABLE: Type confusion - trusting client-provided type info
        String result;
        if (value == null) {
            result = "null value";
        } else if (value instanceof String s) {
            // VULNERABLE: Processing untrusted string input
            result = "String: " + s;
        } else if (value instanceof Integer i) {
            result = "Integer: " + i;
        } else if (value instanceof List<?> list) {
            // VULNERABLE: Processing untrusted list data
            result = "List size: " + list.size();
        } else if (value instanceof Map<?, ?> map) {
            // VULNERABLE: Processing untrusted nested data without validation
            result = "Map: " + map.toString();
        } else {
            // VULNERABLE: Exposing class name of arbitrary objects
            result = "Unknown: " + value.getClass().getName();
        }

        return ResponseEntity.ok(Map.of("result", result));
    }

    /**
     * VULNERABLE: Stream with resource leak and path traversal
     */
    @GetMapping("/logs")
    public ResponseEntity<?> readLogs(@RequestParam String logFile) {
        // VULNERABLE: Path traversal - logFile can contain ../
        // VULNERABLE: Resource leak - stream not properly closed
        Stream<String> lines = null;
        try {
            // VULNERABLE: Stream not properly closed in all code paths
            lines = Files.lines(Path.of("/var/log/" + logFile));

            List<String> errorLines = lines
                .filter(line -> line.contains("ERROR"))
                .limit(100)
                .toList();

            // VULNERABLE: Stream only closed on success path
            lines.close();

            return ResponseEntity.ok(Map.of("errors", errorLines));

        } catch (IOException e) {
            // VULNERABLE: Stream not closed on exception path (resource leak)
            // VULNERABLE: Exposing internal error message
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage()));
        }
    }

    /**
     * VULNERABLE: Var type hiding security-relevant info
     */
    @PostMapping("/config")
    public ResponseEntity<?> updateConfig(@RequestBody Map<String, String> config) {
        // VULNERABLE: var hides that this is user-controlled input
        var dbHost = config.get("database.host");
        var dbPort = config.get("database.port");
        var adminPassword = config.get("admin.password");

        // VULNERABLE: Logging sensitive config including password
        System.out.println("Config update - host: " + dbHost +
                          ", port: " + dbPort +
                          ", admin password: " + adminPassword);

        // VULNERABLE: Exposing all config in response
        return ResponseEntity.ok(Map.of(
            "updated", config,
            "status", "Configuration applied"
        ));
    }

    // Record definitions - auto-generate potentially dangerous toString()
    public record SearchRequest(String term, String sortBy) {}
    public record CommandRequest(String command, List<String> arguments) {}

    // VULNERABLE: Record exposes password in auto-generated toString()
    public record UserRecord(String username, String email, String password, String role) {}
}
