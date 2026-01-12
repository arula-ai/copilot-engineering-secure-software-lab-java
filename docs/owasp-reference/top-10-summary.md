# OWASP Top 10 (2021) Quick Reference

## Overview

The OWASP Top 10 represents the most critical web application security risks. Use this reference during labs to identify and categorize vulnerabilities.

---

## A01: Broken Access Control (↑ from #5)

**What:** Failures in enforcing user permissions and access restrictions.

**Common Patterns:**
- Missing authorization checks on endpoints
- Insecure Direct Object Reference (IDOR)
- Bypassing access controls via URL manipulation
- Mass assignment vulnerabilities
- CORS misconfiguration

**Detection Prompts:**
```
Review this code for access control vulnerabilities:
- Are authorization checks present on all endpoints?
- Can users access other users' data by changing IDs?
- Are role checks properly enforced?
```

**CWEs:** CWE-200, CWE-201, CWE-352, CWE-639

---

## A02: Cryptographic Failures (↑ from #3)

**What:** Failures related to cryptography that expose sensitive data.

**Common Patterns:**
- Plain text password storage
- Weak hashing algorithms (MD5, SHA1)
- Hardcoded secrets/keys
- Missing encryption for sensitive data
- Weak random number generation

**Detection Prompts:**
```
Review this code for cryptographic issues:
- Are passwords properly hashed (bcrypt/argon2)?
- Are secrets hardcoded?
- Is sensitive data encrypted at rest?
```

**CWEs:** CWE-259, CWE-327, CWE-328, CWE-330

---

## A03: Injection (↓ from #1)

**What:** User input interpreted as commands or queries.

**Common Patterns:**
- SQL injection via string concatenation
- Command injection
- NoSQL injection
- LDAP injection
- Template injection

**Detection Prompts:**
```
Review this code for injection vulnerabilities:
- Are queries parameterized?
- Is user input ever concatenated into SQL/commands?
- Are all inputs validated and sanitized?
```

**CWEs:** CWE-79, CWE-89, CWE-94, CWE-78

---

## A04: Insecure Design (NEW)

**What:** Flaws in design and architecture, not implementation bugs.

**Common Patterns:**
- Missing threat modeling
- No rate limiting design
- Trust assumptions about client
- Insufficient business logic validation
- Missing security requirements

**Detection Prompts:**
```
Review this design for security flaws:
- What could go wrong in this flow?
- Are there rate limits?
- What happens if input is malicious?
```

**CWEs:** CWE-209, CWE-256, CWE-501

---

## A05: Security Misconfiguration (↓ from #6)

**What:** Insecure default settings or missing security hardening.

**Common Patterns:**
- Debug mode in production
- Default credentials
- Verbose error messages
- Missing security headers
- Unnecessary features enabled

**Detection Prompts:**
```
Review this configuration for security issues:
- Are there debug endpoints?
- Are default settings changed?
- Are error messages sanitized?
```

**CWEs:** CWE-16, CWE-611, CWE-1004

---

## A06: Vulnerable and Outdated Components

**What:** Using components with known vulnerabilities.

**Common Patterns:**
- Outdated npm packages
- Unpatched frameworks
- End-of-life libraries
- Missing security updates

**Detection Prompts:**
```
Review dependencies for vulnerabilities:
- Run: npm audit
- Run: npx snyk test
- Check last update dates
```

**CWEs:** CWE-1104

---

## A07: Identification and Authentication Failures (↓ from #2)

**What:** Broken authentication mechanisms.

**Common Patterns:**
- Weak password policies
- Missing brute force protection
- Session fixation
- Token leakage
- Credential stuffing vulnerability

**Detection Prompts:**
```
Review authentication for security issues:
- Is there account lockout?
- Are sessions properly invalidated?
- Are tokens cryptographically secure?
```

**CWEs:** CWE-287, CWE-384, CWE-613

---

## A08: Software and Data Integrity Failures (NEW)

**What:** Code and data integrity not verified.

**Common Patterns:**
- No signature verification on webhooks
- Insecure deserialization
- Missing integrity checks on updates
- CI/CD pipeline vulnerabilities

**Detection Prompts:**
```
Review code for integrity issues:
- Are webhook signatures verified?
- Is serialized data validated?
- Are CI/CD pipelines secured?
```

**CWEs:** CWE-502, CWE-829

---

## A09: Security Logging and Monitoring Failures (↓ from #10)

**What:** Insufficient logging for detecting attacks.

**Common Patterns:**
- No logging of security events
- Sensitive data in logs
- No alerting on suspicious activity
- Logs not protected

**Detection Prompts:**
```
Review logging for security issues:
- Are auth events logged?
- Is sensitive data excluded from logs?
- Are logs tamper-proof?
```

**CWEs:** CWE-117, CWE-223, CWE-532, CWE-778

---

## A10: Server-Side Request Forgery (NEW)

**What:** Server makes requests to attacker-controlled destinations.

**Common Patterns:**
- Unvalidated URL fetch
- Access to internal services
- Cloud metadata exposure
- DNS rebinding

**Detection Prompts:**
```
Review for SSRF vulnerabilities:
- Are URLs validated against an allowlist?
- Can internal IPs be accessed?
- Are redirects followed blindly?
```

**CWEs:** CWE-918

---

## Quick Reference Table

| Code | Category | Copilot Detection | Lab Files |
|------|----------|-------------------|-----------|
| A01 | Access Control | High | auth-controller.ts, resource-controller.ts |
| A02 | Cryptography | Medium | password-handler.ts, token-manager.ts |
| A03 | Injection | High | user-repository.ts, query-builder.ts |
| A04 | Insecure Design | Low | payment-handler.ts |
| A05 | Misconfiguration | Medium | user-api.ts |
| A06 | Components | Low | vulnerable-deps.ts |
| A07 | Authentication | High | auth-controller.ts, session-manager.ts |
| A08 | Integrity | Medium | token-manager.ts, payment-handler.ts |
| A09 | Logging | High | auth-controller.ts, payment-handler.ts |
| A10 | SSRF | Medium | resource-controller.ts, file-handler.ts |
