# Secure Software Development Lab - Copilot Instructions

This repository is a **security training lab** containing intentionally vulnerable Java code.

## Repository Context

- `src/main/java/com/securelabs/vulnerable/` - **INTENTIONALLY VULNERABLE** code for learning
- `src/main/java/com/securelabs/secure/` - Reference implementations showing secure patterns
- `exercises/` - Lab instructions and answer keys
- `threat-models/` - STRIDE templates and examples

## Security Analysis Guidelines

When analyzing code in this repository:

1. **Identify OWASP Top 10 vulnerabilities** - Focus on A01-A10 categories
2. **Provide line numbers** - Always reference specific lines where vulnerabilities exist
3. **Explain attack scenarios** - Describe how an attacker could exploit each issue
4. **Suggest secure alternatives** - Reference the `secure/` implementations as models
5. **Use severity ratings** - Critical, High, Medium, Low

## Java Security Patterns to Check

- SQL injection via string concatenation (use PreparedStatement)
- Command injection via Runtime.exec or ProcessBuilder
- Path traversal in file operations (normalize and validate paths)
- Weak cryptography (MD5, SHA1 for passwords - use BCrypt)
- Hardcoded secrets and weak JWT configurations
- Missing authentication/authorization checks
- SSRF vulnerabilities in URL fetching
- Insecure session management
- Sensitive data exposure in logs/responses
- Race conditions with parallel streams

## Code Review Standards

When reviewing fixes:
- Verify PreparedStatement usage for all database queries
- Check BCryptPasswordEncoder with cost factor >= 12
- Ensure constant-time comparison for security tokens
- Validate HMAC signatures on webhooks
- Confirm path normalization with startsWith() checks
- Check for proper try-with-resources on streams

## Lab-Specific Behavior

- When asked to find vulnerabilities, be thorough - this lab has 62 documented issues
- Reference the answer key in `exercises/lab1-identification/answer-key.md` for validation
- For STRIDE analysis, use the template in `threat-models/templates/stride-template.md`
- Always suggest fixes that match patterns in the `secure/` implementations
