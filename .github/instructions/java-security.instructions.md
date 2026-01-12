---
applyTo: "**/*.java"
---

# Java Security Coding Standards

These instructions apply to all Java files in this repository.

## SQL Injection Prevention

**ALWAYS use PreparedStatement with parameterized queries:**

```java
// NEVER do this
String query = "SELECT * FROM users WHERE id = '" + userId + "'";
Statement stmt = conn.createStatement();
stmt.executeQuery(query);

// ALWAYS do this
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setString(1, userId);
ResultSet rs = stmt.executeQuery();
```

**For dynamic column names, use whitelists:**
```java
private static final Set<String> ALLOWED_COLUMNS = Set.of("id", "name", "email", "created_at");

public List<User> findUsers(String sortColumn) {
    if (!ALLOWED_COLUMNS.contains(sortColumn)) {
        sortColumn = "id"; // Default to safe value
    }
    // sortColumn is now safe to use in query
}
```

## Password Handling

**Use BCrypt with appropriate work factor:**
```java
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12); // Cost factor 12+
String hashedPassword = encoder.encode(rawPassword);
boolean matches = encoder.matches(rawPassword, hashedPassword);
```

**NEVER:**
- Use MD5, SHA1, or SHA256 for passwords
- Store passwords in plain text
- Log passwords (even hashed)
- Return passwords in API responses

## Cryptographic Security

**For random tokens, use SecureRandom:**
```java
SecureRandom secureRandom = new SecureRandom();
byte[] token = new byte[32]; // 256 bits
secureRandom.nextBytes(token);
String tokenString = Base64.getUrlEncoder().withoutPadding().encodeToString(token);
```

**NEVER use:**
- `Math.random()` for security-sensitive operations
- `UUID.randomUUID()` for session tokens
- Predictable values (timestamps, sequential IDs)

## Path Traversal Prevention

**Always normalize and validate paths:**
```java
Path basePath = Paths.get("/var/data").toAbsolutePath().normalize();
Path requestedPath = basePath.resolve(userInput).normalize();

if (!requestedPath.startsWith(basePath)) {
    throw new SecurityException("Path traversal attempt detected");
}
```

## Input Validation

**Validate all external input:**
- Validate length limits
- Validate format with whitelist patterns
- Validate against business rules
- Sanitize before output

```java
// Email validation
if (!email.matches("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$")) {
    throw new ValidationException("Invalid email format");
}

// Filename validation
if (!filename.matches("^[a-zA-Z0-9_-]+\\.[a-zA-Z0-9]+$")) {
    throw new ValidationException("Invalid filename format");
}
```

## Authentication & Session Management

**Cookie security flags:**
```java
Cookie cookie = new Cookie("session", sessionId);
cookie.setHttpOnly(true);    // Prevent XSS access
cookie.setSecure(true);      // HTTPS only
cookie.setPath("/");
cookie.setMaxAge(3600);      // 1 hour
// Set SameSite via response header
response.setHeader("Set-Cookie", cookie.getName() + "=" + cookie.getValue() +
    "; HttpOnly; Secure; SameSite=Strict; Path=/");
```

**Account lockout:**
```java
private static final int MAX_FAILED_ATTEMPTS = 5;
private static final long LOCKOUT_DURATION_MS = 30 * 60 * 1000; // 30 minutes

if (failedAttempts >= MAX_FAILED_ATTEMPTS) {
    lockAccount(userId, LOCKOUT_DURATION_MS);
    throw new AuthenticationException("Account temporarily locked");
}
```

## Authorization

**Always verify resource ownership:**
```java
public Resource getResource(String resourceId, String currentUserId) {
    Resource resource = resourceRepository.findById(resourceId);

    if (!resource.getOwnerId().equals(currentUserId) && !isAdmin(currentUserId)) {
        throw new AccessDeniedException("Not authorized to access this resource");
    }

    return resource;
}
```

## Error Handling

**Never expose internal details:**
```java
// WRONG
catch (SQLException e) {
    return ResponseEntity.status(500).body("Database error: " + e.getMessage());
}

// CORRECT
catch (SQLException e) {
    log.error("Database error processing request", e);
    return ResponseEntity.status(500).body(Map.of("error", "An error occurred"));
}
```

## Logging

**Security event logging (what to log):**
- Authentication attempts (success and failure)
- Authorization failures
- Input validation failures
- Security configuration changes

**Never log:**
- Passwords or password hashes
- Session tokens or API keys
- Credit card numbers (mask to last 4)
- CVV codes (never store or log)

```java
// CORRECT logging
log.info("Login successful for user: {}", userId);
log.warn("Failed login attempt for user: {} from IP: {}", userId, clientIp);
log.error("Authorization denied for user: {} accessing resource: {}", userId, resourceId);

// WRONG - contains sensitive data
log.info("User {} logged in with password {}", userId, password);
```

## Resource Management

**Always use try-with-resources:**
```java
try (Connection conn = dataSource.getConnection();
     PreparedStatement stmt = conn.prepareStatement(query);
     ResultSet rs = stmt.executeQuery()) {
    // Process results
}
```

## Thread Safety

**Use thread-safe collections for concurrent access:**
```java
// WRONG - race condition with parallel streams
List<String> results = new ArrayList<>();
items.parallelStream().forEach(item -> results.add(process(item)));

// CORRECT - thread-safe collection
List<String> results = Collections.synchronizedList(new ArrayList<>());
// Or use ConcurrentHashMap for maps
ConcurrentHashMap<String, Integer> counts = new ConcurrentHashMap<>();
```
