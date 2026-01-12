# Lab 1 Answer Key: Vulnerability Identification (Java)

## Summary

Total vulnerabilities documented: **27**
Target for participants: **15+**

---

## AuthController.java (7 vulnerabilities)

| # | Line | OWASP | Severity | Vulnerability | Fix |
|---|------|-------|----------|---------------|-----|
| 1 | 45 | A09 | High | Password logged in plain text | Remove password from log statement |
| 2 | 52 | A07 | High | User enumeration via different error messages | Use generic "Authentication failed" message |
| 3 | 57 | A02 | Critical | MD5 password hashing | Use BCryptPasswordEncoder with cost 12+ |
| 4 | 63 | A07 | High | No account lockout after failed attempts | Implement lockout after 5 failures |
| 5 | 70 | A07 | High | Insecure cookie (no httpOnly, secure, sameSite) | Add all security flags to cookie |
| 6 | 79 | A09 | High | Password hash exposed in response | Remove passwordHash from response |
| 7 | 94-106 | A01 | Critical | IDOR - no authorization check for user access | Verify requesting user owns resource |

---

## PaymentHandler.java (6 vulnerabilities)

| # | Line | OWASP | Severity | Vulnerability | Fix |
|---|------|-------|----------|---------------|-----|
| 8 | 35-37 | A09 | Critical | Full card number and CVV logged (PCI violation) | Never log card data |
| 9 | 42 | A04 | High | No validation on payment amount | Validate: positive, max limit, decimal places |
| 10 | 53-54 | A09 | High | Card number and CVV stored in transaction | Store only last 4 digits, never CVV |
| 11 | 70-75 | A01 | High | No authorization check for refund | Verify user owns transaction |
| 12 | 82-90 | A08 | High | Webhook without signature verification | Implement HMAC signature validation |
| 13 | 100-110 | A01 | High | Transaction details exposed without auth | Require authentication |

---

## UserRepository.java (5 vulnerabilities)

| # | Line | OWASP | Severity | Vulnerability | Fix |
|---|------|-------|----------|---------------|-----|
| 14 | 25-30 | A03 | Critical | SQL injection via string concatenation | Use PreparedStatement with parameters |
| 15 | 38-42 | A03 | Critical | SQL injection in search with LIKE | Parameterize and escape wildcards |
| 16 | 55-60 | A03 | Critical | SQL injection with dynamic column names | Whitelist allowed columns |
| 17 | 90-95 | A03 | Critical | Command injection via Runtime.exec | Use database export API instead |
| 18 | 105-110 | A01 | High | Path traversal in file operations | Validate and normalize paths |

---

## ResourceController.java (4 vulnerabilities)

| # | Line | OWASP | Severity | Vulnerability | Fix |
|---|------|-------|----------|---------------|-----|
| 19 | 45-65 | A10 | Critical | SSRF - fetches arbitrary URLs | Allowlist domains, block internal IPs |
| 20 | 30 | A05 | High | CORS wildcard with credentials | Specify allowed origins |
| 21 | 80-85 | A01 | High | Open redirect vulnerability | Validate redirect URLs against allowlist |
| 22 | 35-42 | A01 | High | IDOR - resource access without auth | Add authorization checks |

---

## TokenManager.java (3 vulnerabilities)

| # | Line | OWASP | Severity | Vulnerability | Fix |
|---|------|-------|----------|---------------|-----|
| 23 | 20 | A02 | Critical | Hardcoded weak JWT secret ("secret") | Use env variable with strong secret |
| 24 | 45-60 | A02 | High | JWT parsed without signature verification | Always verify signature |
| 25 | 70-80 | A08 | High | 'none' algorithm token creation | Never allow 'none' algorithm |

---

## Other Files (2 vulnerabilities)

| # | File | OWASP | Severity | Vulnerability | Fix |
|---|------|-------|----------|---------------|-----|
| 26 | PasswordHandler.java:25 | A02 | Critical | MD5 hashing with timing-unsafe comparison | Use BCrypt with constant-time comparison |
| 27 | pom.xml | A06 | Critical | log4j-core 2.14.1 (CVE-2021-44228 Log4Shell) | Upgrade to 2.17.1+ |

---

## Vulnerability Distribution by OWASP Category

| Category | Count | Files |
|----------|-------|-------|
| A01: Access Control | 7 | AuthController, PaymentHandler, ResourceController, UserRepository |
| A02: Cryptography | 5 | AuthController, PasswordHandler, TokenManager |
| A03: Injection | 5 | UserRepository, QueryBuilder |
| A04: Insecure Design | 1 | PaymentHandler |
| A05: Misconfiguration | 1 | ResourceController |
| A06: Vulnerable Components | 1 | pom.xml |
| A07: Authentication | 3 | AuthController |
| A08: Integrity | 2 | PaymentHandler, TokenManager |
| A09: Logging | 4 | AuthController, PaymentHandler |
| A10: SSRF | 2 | ResourceController, UserRepository |

---

## Critical Vulnerabilities (Immediate Action Required)

1. **SQL Injection** (UserRepository.java) - Database compromise
2. **Log4Shell** (pom.xml) - Remote code execution
3. **Card Data Logging** (PaymentHandler.java) - PCI violation
4. **SSRF** (ResourceController.java) - Internal network access
5. **Weak JWT Secret** (TokenManager.java) - Authentication bypass
