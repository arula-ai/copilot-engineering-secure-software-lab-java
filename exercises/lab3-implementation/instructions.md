# Lab 3: Implementing Secure Patterns with GitHub Copilot (Java)

**Duration:** 35 minutes
**Objective:** Fix vulnerabilities identified in Labs 1 & 2 using secure Java/Spring Boot coding patterns.

---

## Important: Copilot-Only Workflow

All code changes must be made using GitHub Copilot:
- Use Copilot Chat for refactoring guidance
- Use inline Copilot suggestions for code completion
- Use `#file` references to include context
- **Do NOT manually type code**

---

## Reference Implementations

Secure reference code is available in `src/main/java/com/securelabs/secure/`:
- `secure/auth/SecureAuthController.java`
- `secure/data/SecureUserRepository.java`
- `secure/api/SecurePaymentHandler.java`

Use these as models when fixing vulnerable code.

---

## Task 1: Secure Authentication (10 min)

**File:** `src/main/java/com/securelabs/vulnerable/auth/AuthController.java`

**Copilot Chat Prompt:**
```
#file:src/main/java/com/securelabs/vulnerable/auth/AuthController.java

Refactor this Spring Boot authentication controller to fix these issues:
1. Add password hashing using BCryptPasswordEncoder (cost factor 12)
2. Implement account lockout after 5 failed attempts for 30 minutes
3. Generate secure session tokens using SecureRandom
4. Remove passwords from logs and responses
5. Use generic error messages to prevent user enumeration
6. Add httpOnly, Secure, and SameSite flags to cookies

Reference the secure implementation in:
#file:src/main/java/com/securelabs/secure/auth/SecureAuthController.java

Generate the complete refactored code.
```

**Apply the changes using Copilot's "Apply in Editor" or inline suggestions.**

### Verify Task 1

Ask Copilot to verify:
```
Review my changes to AuthController.java.
Confirm these security issues are fixed:
- Password hashing with BCrypt
- Account lockout
- Secure cookies
- No sensitive data in logs/responses
```

---

## Task 2: Secure Payment Processing (10 min)

**File:** `src/main/java/com/securelabs/vulnerable/api/PaymentHandler.java`

**Copilot Chat Prompt:**
```
#file:src/main/java/com/securelabs/vulnerable/api/PaymentHandler.java

Fix these security issues in the payment handler:

1. INPUT VALIDATION:
   - Amount: positive number, max $1,000,000, 2 decimal places
   - Currency: whitelist (USD, EUR, GBP only)
   - Payment token: validate format, never accept raw card numbers

2. AUTHORIZATION:
   - Verify user owns the transaction before refund
   - Add role check for admin-only operations

3. LOGGING:
   - Remove all credit card data from logs
   - Log security events without sensitive data

4. WEBHOOK SECURITY:
   - Add HMAC signature verification using javax.crypto.Mac
   - Validate timestamp to prevent replay attacks

Reference: #file:src/main/java/com/securelabs/secure/api/SecurePaymentHandler.java

Generate the secure implementation.
```

### Verify Task 2

```
Check my PaymentHandler.java changes:
- Is credit card data removed from all logs?
- Are amounts properly validated?
- Is HMAC webhook signature verification implemented?
```

---

## Task 3: Fix SQL Injection (8 min)

**File:** `src/main/java/com/securelabs/vulnerable/data/UserRepository.java`

**Copilot Chat Prompt:**
```
#file:src/main/java/com/securelabs/vulnerable/data/UserRepository.java

Convert all SQL queries to use PreparedStatement:

1. findByEmail - use PreparedStatement with parameter binding
2. searchUsers - use PreparedStatement for LIKE with validated ORDER BY whitelist
3. findByQuery - whitelist allowed fields before query
4. exportUsers - remove Runtime.exec command injection (use JDBC ResultSet export)
5. getUserAvatar - add path traversal protection with Path.normalize()

Show the vulnerable pattern and the secure replacement for each.

Reference: #file:src/main/java/com/securelabs/secure/data/SecureUserRepository.java
```

### Verify Task 3

```
#file:src/main/java/com/securelabs/vulnerable/data/UserRepository.java

Are there any remaining injection vulnerabilities in this file?
Check for SQL injection, command injection, and path traversal.
```

---

## Task 4: Fix SSRF and Access Control (7 min)

**File:** `src/main/java/com/securelabs/vulnerable/api/ResourceController.java`

**Copilot Chat Prompt:**
```
#file:src/main/java/com/securelabs/vulnerable/api/ResourceController.java

Fix these critical vulnerabilities:

1. SSRF PREVENTION:
   - Add URL allowlist for external fetches
   - Block internal IP ranges (10.x, 172.16.x, 192.168.x, 169.254.x)
   - Only allow HTTPS
   - Disable redirect following with setInstanceFollowRedirects(false)

2. AUTHORIZATION:
   - Add authentication check to all endpoints
   - Verify resource ownership before access
   - Log authorization failures

3. OPEN REDIRECT:
   - Validate redirect URLs against allowlist
   - Only allow relative URLs or trusted domains

4. CORS:
   - Replace @CrossOrigin(origins = "*") with specific allowed origins
   - Remove allowCredentials when using multiple origins
```

---

## Final Verification

### Run Build

Ask Copilot:
```
#runInTerminal mvn clean compile
```

### Run Tests

```
#runInTerminal mvn test
```

### Security Review

**Copilot Chat Prompt:**
```
@workspace Review all Java files in src/main/java/com/securelabs/vulnerable/ that I modified.
For each file, confirm:
1. Original vulnerabilities are fixed
2. No new vulnerabilities introduced
3. Code follows Spring Security best practices

List any remaining issues.
```

---

## Success Criteria

Your fixes should address:

| Category | Requirements | Verified |
|----------|--------------|----------|
| Authentication | BCrypt, lockout, secure tokens | ☐ |
| Input Validation | Amount, currency, token validation | ☐ |
| Authorization | Ownership checks, role verification | ☐ |
| Injection | PreparedStatement, no concatenation | ☐ |
| SSRF | URL allowlist, block internal IPs | ☐ |
| Logging | No sensitive data in logs | ☐ |
| Webhooks | HMAC signature verification | ☐ |

---

## Compare with Solutions

After completing the lab, compare your implementations with:
- `src/main/java/com/securelabs/secure/auth/SecureAuthController.java`
- `src/main/java/com/securelabs/secure/api/SecurePaymentHandler.java`
- `src/main/java/com/securelabs/secure/data/SecureUserRepository.java`

---

## Bonus Challenge

If time permits, fix the JWT vulnerabilities:

```
#file:src/main/java/com/securelabs/vulnerable/session/TokenManager.java

Fix the JWT security issues:
1. Reject 'none' algorithm
2. Use cryptographically secure secret from environment variable
3. Add token expiration with setExpiration()
4. Implement refresh token rotation

Reference: Use jjwt library best practices.
```
