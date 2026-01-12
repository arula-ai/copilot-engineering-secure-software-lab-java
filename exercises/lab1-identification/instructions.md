# Lab 1: Vulnerability Identification with GitHub Copilot (Java)

**Duration:** 30 minutes
**Objective:** Identify OWASP Top 10 vulnerabilities in the intentionally vulnerable Java code.

---

## Important: Copilot-Only Workflow

All analysis must be performed using GitHub Copilot Chat. Do NOT manually review code without Copilot assistance.

---

## Target Files

Analyze these files in order of priority:

| Priority | File | Expected Vulnerabilities |
|----------|------|-------------------------|
| 1 | `vulnerable/auth/AuthController.java` | A01, A02, A07, A09 |
| 2 | `vulnerable/api/PaymentHandler.java` | A01, A04, A08, A09 |
| 3 | `vulnerable/data/UserRepository.java` | A03, A10 |
| 4 | `vulnerable/api/ResourceController.java` | A01, A05, A10 |
| 5 | `vulnerable/session/TokenManager.java` | A02, A08 |
| 6 | `vulnerable/auth/PasswordHandler.java` | A02 |
| 7 | `vulnerable/auth/SessionManager.java` | A02, A07 |
| 8 | `vulnerable/data/QueryBuilder.java` | A03 |
| 9 | `vulnerable/data/FileHandler.java` | A01, A08, A10 |
| 10 | `vulnerable/api/UserApi.java` | A01, A03, A05, A09 |
| 11 | `vulnerable/api/ModernApiHandler.java` | A01, A03, A10 (Java 17+) |
| 12 | `pom.xml` | A06 |

---

## Step-by-Step Instructions

### Step 1: Initial Reconnaissance (5 min)

Use Copilot Chat to get an overview:

```
@workspace List all Java files in src/main/java/com/securelabs/vulnerable/
and briefly describe what each file does based on its name and package.
```

### Step 2: Deep Analysis (20 min)

For each target file, use this analysis prompt:

```
#file:src/main/java/com/securelabs/vulnerable/auth/AuthController.java

Analyze this Java file for security vulnerabilities.
For each vulnerability found, provide:
1. OWASP Top 10 category (A01-A10)
2. Severity (Critical/High/Medium/Low)
3. Line number(s) where the vulnerability exists
4. Attack scenario explaining how an attacker could exploit it
5. Recommended fix with Java code example

Focus on: SQL injection, authentication flaws, authorization issues,
cryptographic failures, injection attacks, and sensitive data exposure.
```

Repeat for each file in the target list.

### Step 3: Dependency Analysis (5 min)

Analyze vulnerable dependencies:

```
#file:pom.xml

Identify any dependencies with known security vulnerabilities (CVEs).
For each vulnerable dependency:
1. Dependency name and version
2. CVE identifier
3. Vulnerability description
4. Recommended secure version
```

---

## Recording Your Findings

Create a vulnerability report using this format:

| # | File | Line | OWASP | Severity | Description | Fix |
|---|------|------|-------|----------|-------------|-----|
| 1 | AuthController.java | 45 | A09 | High | Password logged in plain text | Remove password from log statement |
| 2 | ... | ... | ... | ... | ... | ... |

---

## Helpful Copilot Prompts

### For SQL Injection
```
Search for SQL injection vulnerabilities where user input is concatenated into SQL strings.
Look for: Statement.executeQuery(), string concatenation with SQL.
```

### For Authentication Issues
```
Find authentication vulnerabilities including:
- Weak password hashing (MD5, SHA1)
- Missing account lockout
- Session fixation
- Insecure cookie settings
```

### For Authorization Flaws
```
Identify missing authorization checks where:
- Users can access other users' data (IDOR)
- Admin functions lack role verification
- Resources are accessed without ownership validation
```

### For SSRF
```
Find SSRF vulnerabilities where:
- User-supplied URLs are fetched without validation
- Internal IP addresses are not blocked
- URL schemes are not restricted
```

---

## Success Criteria

- [ ] Analyzed all 10 target files
- [ ] Identified at least 15 distinct vulnerabilities
- [ ] Documented OWASP category for each
- [ ] Provided attack scenario for critical/high issues
- [ ] Suggested fixes for at least 5 vulnerabilities

---

## Compare with Answer Key

After completing your analysis, compare with:
`exercises/lab1-identification/answer-key.md`

**Target: 15+ of 27 documented vulnerabilities**
