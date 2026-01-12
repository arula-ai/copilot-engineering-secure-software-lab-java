---
name: Find Vulnerabilities
description: Systematically scan a file or codebase for OWASP Top 10 security vulnerabilities
mode: agent
tools: ['codebase', 'search', 'file']
---

# Security Vulnerability Scan

Analyze the specified file(s) for security vulnerabilities. For each vulnerability found, provide:

## Analysis Template

For each vulnerability, document:

1. **OWASP Category** (A01-A10)
2. **CWE Identifier**
3. **Severity** (Critical/High/Medium/Low)
4. **File and Line Number**
5. **Vulnerable Code Snippet**
6. **Attack Scenario** - How could this be exploited?
7. **Recommended Fix** - Code example of the secure pattern

## Vulnerability Checklist

### Injection (A03)
- [ ] SQL injection via string concatenation
- [ ] Command injection via Runtime.exec/ProcessBuilder
- [ ] LDAP injection
- [ ] Template injection

### Broken Access Control (A01)
- [ ] Missing authentication checks
- [ ] Missing authorization/ownership verification
- [ ] IDOR (Insecure Direct Object Reference)
- [ ] CORS misconfiguration

### Cryptographic Failures (A02)
- [ ] Weak password hashing (MD5, SHA1)
- [ ] Hardcoded secrets/keys
- [ ] Weak random number generation
- [ ] Missing encryption

### Security Misconfiguration (A05)
- [ ] Debug endpoints
- [ ] Verbose error messages
- [ ] Default credentials

### Vulnerable Components (A06)
- [ ] Known CVEs in dependencies

### Authentication Failures (A07)
- [ ] No account lockout
- [ ] User enumeration
- [ ] Session fixation
- [ ] Insecure cookies

### Integrity Failures (A08)
- [ ] Unsigned webhooks
- [ ] JWT 'none' algorithm
- [ ] Insecure deserialization

### Logging Failures (A09)
- [ ] Passwords in logs
- [ ] Sensitive data exposure
- [ ] Missing security event logging

### SSRF (A10)
- [ ] Unvalidated URL fetching
- [ ] Internal IP access
- [ ] Protocol restrictions missing

## Output Format

```markdown
## Vulnerability Report: [Filename]

### Summary
- Total vulnerabilities found: X
- Critical: X | High: X | Medium: X | Low: X

### Findings

#### 1. [A0X] Vulnerability Name
**Severity:** Critical
**Line:** XX
**CWE:** CWE-XXX

**Vulnerable Code:**
```java
// code here
```

**Attack Scenario:**
An attacker could...

**Recommended Fix:**
```java
// secure code here
```

---
[Repeat for each finding]
```

Begin the analysis now. Be thorough - this lab contains 62 documented vulnerabilities.
