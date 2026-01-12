# Lab 1 Answer Key: Vulnerability Identification (Java)

## Summary

Total vulnerabilities documented: **62**
Target for participants: **25+**

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
| 23 | 23 | A02 | Critical | Hardcoded weak JWT secret ("secret") | Use env variable with 256-bit+ key |
| 24 | 75-105 | A02 | Critical | JWT parsed without signature verification | Always verify signature before using claims |
| 25 | 111-121 | A08 | Critical | 'none' algorithm token creation | Never create/accept unsigned tokens |

---

## PasswordHandler.java (2 vulnerabilities)

| # | Line | OWASP | Severity | Vulnerability | Fix |
|---|------|-------|----------|---------------|-----|
| 26 | 25 | A02 | Critical | MD5 hashing - cryptographically broken | Use BCryptPasswordEncoder with cost 12+ |
| 27 | 61-79 | A02 | High | Timing-unsafe password comparison | Use MessageDigest.isEqual() for constant-time |

---

## SessionManager.java (5 vulnerabilities)

| # | Line | OWASP | Severity | Vulnerability | Fix |
|---|------|-------|----------|---------------|-----|
| 28 | 28-43 | A02 | High | Weak session token (UUID not crypto-secure) | Use SecureRandom for token generation |
| 29 | 50-59 | A02 | Critical | Sequential predictable session IDs | Use cryptographically random tokens |
| 30 | 64-75 | A07 | High | No session expiration check | Add timestamp validation and timeout |
| 31 | 89-95 | A07 | Critical | Session fixation vulnerability | Regenerate session ID on login |
| 32 | 113-116 | A05 | High | Debug endpoint exposes all sessions | Remove or protect debug endpoints |

---

## QueryBuilder.java (6 vulnerabilities)

| # | Line | OWASP | Severity | Vulnerability | Fix |
|---|------|-------|----------|---------------|-----|
| 33 | 39-44 | A03 | Critical | SQL injection in WHERE clause | Use parameterized queries |
| 34 | 49-53 | A03 | Critical | Raw SQL condition injection | Validate and sanitize input |
| 35 | 58-62 | A03 | High | Unvalidated ORDER BY clause | Whitelist allowed columns |
| 36 | 125-138 | A03 | Critical | SQL injection in INSERT | Use PreparedStatement |
| 37 | 143-157 | A03 | Critical | SQL injection in UPDATE | Use PreparedStatement |
| 38 | 170-173 | A03 | Critical | UNION injection vulnerability | Disallow UNION operations |

---

## FileHandler.java (7 vulnerabilities)

| # | Line | OWASP | Severity | Vulnerability | Fix |
|---|------|-------|----------|---------------|-----|
| 39 | 27-34 | A01 | Critical | Path traversal in file read | Normalize and validate paths |
| 40 | 39-44 | A01 | Critical | Path traversal in file write | Normalize and validate paths |
| 41 | 49-57 | A08 | High | Incomplete extension blacklist | Use whitelist instead |
| 42 | 77-101 | A10 | Critical | SSRF in URL fetching | Allowlist domains, block internal IPs |
| 43 | 106-118 | A10 | Critical | SSRF with file:// protocol | Restrict to HTTPS only |
| 44 | 123-132 | A01 | High | Directory listing exposure | Restrict directory access |
| 45 | 156-173 | A01 | Critical | Zip slip vulnerability | Validate entry paths |

---

## UserApi.java (8 vulnerabilities)

| # | Line | OWASP | Severity | Vulnerability | Fix |
|---|------|-------|----------|---------------|-----|
| 46 | 34-51 | A01 | Critical | List users without authentication | Require authentication |
| 47 | 46 | A09 | Critical | Password exposed in API response | Never return passwords |
| 48 | 56-74 | A01 | High | IDOR - access any user by ID | Add authorization check |
| 49 | 102-129 | A01 | Critical | Mass assignment - role escalation | Whitelist allowed fields |
| 50 | 134-147 | A01 | High | Delete without authorization | Require admin role |
| 51 | 152-162 | A05 | Critical | Debug endpoint in production | Remove or restrict access |
| 52 | 167-178 | A01 | Critical | Admin endpoint without auth | Require admin authentication |
| 53 | 183-203 | A04 | High | Bulk create with default admin role | Validate roles, require auth |

---

## ModernApiHandler.java - Java 17+ Patterns (8 vulnerabilities)

| # | Line | OWASP | Severity | Vulnerability | Fix |
|---|------|-------|----------|---------------|-----|
| 54 | 50-57 | A03 | Critical | SQL injection via text block + formatted() | Use PreparedStatement with parameters |
| 55 | 72-102 | A10 | Critical | SSRF via Java HttpClient with auto-redirect | Allowlist domains, block internal IPs |
| 56 | 109-137 | A10 | High | Async SSRF via CompletableFuture | Validate all URLs, rate limit |
| 57 | 144-163 | A01 | High | Race condition with parallel streams | Use thread-safe collections |
| 58 | 170-198 | A03 | Critical | Command injection via ProcessBuilder | Never execute user-provided commands |
| 59 | 203-223 | A01 | Critical | Path traversal with Files API | Normalize and validate paths |
| 60 | 257-272 | A09 | High | Record toString() exposes password | Override toString() to exclude sensitive data |
| 61 | 308-331 | A01 | Medium | Stream resource leak + path traversal | Use try-with-resources |

---

## pom.xml (1 vulnerability)

| # | File | OWASP | Severity | Vulnerability | Fix |
|---|------|-------|----------|---------------|-----|
| 62 | pom.xml:102 | A06 | Critical | log4j-core 2.14.1 (CVE-2021-44228 Log4Shell) | Upgrade to 2.17.1+ |

---

## Vulnerability Distribution by OWASP Category

| Category | Count | Files |
|----------|-------|-------|
| A01: Access Control | 22 | AuthController, PaymentHandler, ResourceController, UserRepository, FileHandler, UserApi, ModernApiHandler |
| A02: Cryptography | 8 | AuthController, PasswordHandler, TokenManager, SessionManager |
| A03: Injection | 14 | UserRepository, QueryBuilder, ModernApiHandler |
| A04: Insecure Design | 2 | PaymentHandler, UserApi |
| A05: Misconfiguration | 3 | ResourceController, SessionManager, UserApi |
| A06: Vulnerable Components | 1 | pom.xml |
| A07: Authentication | 5 | AuthController, SessionManager |
| A08: Integrity | 3 | PaymentHandler, TokenManager, FileHandler |
| A09: Logging | 6 | AuthController, PaymentHandler, UserApi, ModernApiHandler |
| A10: SSRF | 6 | ResourceController, UserRepository, FileHandler, ModernApiHandler |

---

## Critical Vulnerabilities (Immediate Action Required)

1. **SQL Injection** (UserRepository.java, QueryBuilder.java) - Database compromise
2. **Log4Shell** (pom.xml) - Remote code execution
3. **Card Data Logging** (PaymentHandler.java) - PCI violation
4. **SSRF** (ResourceController.java, FileHandler.java, ModernApiHandler.java) - Internal network access
5. **Weak JWT Secret** (TokenManager.java) - Authentication bypass
6. **Session Fixation** (SessionManager.java) - Session hijacking
7. **Path Traversal** (FileHandler.java, ModernApiHandler.java) - Arbitrary file access
8. **Mass Assignment** (UserApi.java) - Privilege escalation
