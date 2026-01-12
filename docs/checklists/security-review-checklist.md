# Security Code Review Checklist

## Input Validation
- [ ] All external inputs validated
- [ ] Whitelist validation used where possible
- [ ] Input length limits enforced
- [ ] Special characters properly handled
- [ ] File uploads validated (type, size, content)

## Authentication
- [ ] Strong password hashing (bcrypt/argon2)
- [ ] Account lockout implemented
- [ ] Session timeout configured
- [ ] Secure session token generation
- [ ] MFA support where required

## Authorization
- [ ] Access control on all protected resources
- [ ] Principle of least privilege applied
- [ ] RBAC/ABAC properly implemented
- [ ] No IDOR vulnerabilities
- [ ] Resource ownership verified

## Data Protection
- [ ] Sensitive data encrypted at rest
- [ ] TLS for data in transit
- [ ] No sensitive data in logs
- [ ] PII properly handled
- [ ] Secrets not hardcoded

## Injection Prevention
- [ ] Parameterized queries used
- [ ] Output encoding applied
- [ ] No command injection
- [ ] Template injection prevented
- [ ] LDAP injection prevented

## Error Handling
- [ ] Generic error messages to users
- [ ] Detailed errors only in logs
- [ ] No stack traces exposed
- [ ] Graceful failure handling

## Logging & Monitoring
- [ ] Security events logged
- [ ] No sensitive data in logs
- [ ] Log injection prevented
- [ ] Audit trail maintained

## OWASP Top 10 Check
- [ ] A01: Broken Access Control
- [ ] A02: Cryptographic Failures
- [ ] A03: Injection
- [ ] A04: Insecure Design
- [ ] A05: Security Misconfiguration
- [ ] A06: Vulnerable Components
- [ ] A07: Auth Failures
- [ ] A08: Data Integrity Failures
- [ ] A09: Logging Failures
- [ ] A10: SSRF
