# Copilot Secure Development Lab - Java

**Workshop:** Secure Software Development with GitHub Copilot
**Duration:** 90 minutes
**Audience:** Java/Spring Boot engineers advancing secure coding skills

---

## WARNING

This repository contains **intentionally vulnerable code** for educational purposes.

**DO NOT:**
- Deploy this code to production
- Use vulnerable patterns in real applications
- Copy code without fixing vulnerabilities

---

## Copilot-Only Workflow

**All lab work must be completed using GitHub Copilot.** This ensures you learn to leverage AI for security tasks.

### How to Use Copilot in This Lab

1. **Copilot Chat** (`Ctrl+Shift+I` / `Cmd+Shift+I`)
   - Analyze code for vulnerabilities
   - Generate secure implementations
   - Create threat models

2. **Inline Suggestions**
   - Type comments starting with `//` to get suggestions
   - Accept suggestions with `Tab`

3. **Terminal Commands**
   - Use `#runInTerminal` in Copilot Chat
   - Example: `#runInTerminal mvn dependency:tree`

4. **File References**
   - Use `#file:path/to/File.java` to include context
   - Use `@workspace` for project-wide queries

**Do NOT manually type code or terminal commands.**

---

## Getting Started

```
# Build the project (via Copilot Chat)
#runInTerminal mvn clean compile

# Run tests
#runInTerminal mvn test

# Run the application
#runInTerminal mvn spring-boot:run

# Check for vulnerable dependencies
#runInTerminal mvn dependency-check:check
```

---

## Lab Structure (90 minutes)

| Time | Lab | Duration | Focus |
|------|-----|----------|-------|
| 0:00 | **Lab 1:** Vulnerability Identification | 30 min | Find OWASP Top 10 issues |
| 0:30 | **Lab 2:** Threat Modeling | 25 min | Create STRIDE threat model |
| 0:55 | **Lab 3:** Secure Implementation | 35 min | Fix vulnerabilities |

---

## Repository Structure

```
copilot-secure-dev-lab-java/
├── src/main/java/com/securelabs/
│   ├── vulnerable/              # Intentionally vulnerable code
│   │   ├── auth/                # Authentication vulnerabilities
│   │   ├── api/                 # API vulnerabilities
│   │   ├── data/                # Injection vulnerabilities
│   │   └── session/             # JWT/session vulnerabilities
│   └── secure/                  # Reference implementations
│       ├── auth/                # Secure auth patterns
│       ├── api/                 # Secure API patterns
│       └── data/                # Secure data patterns
├── src/test/java/               # Security verification tests
├── exercises/
│   ├── lab1-identification/     # Vulnerability hunting
│   ├── lab2-threat-model/       # STRIDE analysis
│   └── lab3-implementation/     # Fixing vulnerabilities
├── threat-models/
│   ├── templates/               # STRIDE template
│   └── examples/                # Completed threat model
└── docs/
    ├── owasp-reference/         # OWASP Top 10 quick reference
    └── checklists/              # Security review checklist
```

---

## OWASP Top 10 Coverage

| Category | Vulnerable Files | Secure Reference |
|----------|-----------------|------------------|
| A01: Access Control | AuthController.java, ResourceController.java | secure/auth/, secure/api/ |
| A02: Cryptography | PasswordHandler.java, TokenManager.java | secure/auth/, secure/session/ |
| A03: Injection | UserRepository.java, QueryBuilder.java | secure/data/ |
| A04: Insecure Design | PaymentHandler.java | secure/api/SecurePaymentHandler.java |
| A05: Misconfiguration | UserApi.java, ResourceController.java | secure/api/ |
| A06: Vulnerable Components | pom.xml (log4j, jackson) | mvn dependency-check |
| A07: Authentication | AuthController.java, SessionManager.java | secure/auth/ |
| A08: Integrity Failures | TokenManager.java, PaymentHandler.java | secure/session/, secure/api/ |
| A09: Logging Failures | AuthController.java, PaymentHandler.java | secure/auth/, secure/api/ |
| A10: SSRF | ResourceController.java, FileHandler.java | secure/api/, secure/data/ |

---

## Quick Start for Each Lab

### Lab 1: Vulnerability Identification

Open: `exercises/lab1-identification/instructions.md`

```
# Copilot Chat prompt to start:
@workspace I'm analyzing this Java codebase for OWASP Top 10 vulnerabilities.
The vulnerable code is in src/main/java/com/securelabs/vulnerable/.
List all the files I should analyze and the expected vulnerabilities in each.
```

### Lab 2: Threat Modeling

Open: `exercises/lab2-threat-model/instructions.md`

```
# Copilot Chat prompt to start:
Create a STRIDE threat model for an authentication and payment system.
The system includes: AuthController, PaymentHandler, SessionManager.
Generate a Mermaid architecture diagram and identify threats for each STRIDE category.
```

### Lab 3: Secure Implementation

Open: `exercises/lab3-implementation/instructions.md`

```
# Copilot Chat prompt to start:
#file:src/main/java/com/securelabs/vulnerable/auth/AuthController.java
Refactor this code to fix all security vulnerabilities.
Use patterns from #file:src/main/java/com/securelabs/secure/auth/SecureAuthController.java as reference.
```

---

## Verification

### Run Security Tests

```
#runInTerminal mvn test
```

### Run Dependency Check

```
#runInTerminal mvn dependency-check:check
```

### Build Project

```
#runInTerminal mvn clean package -DskipTests
```

---

## Key Resources

| Resource | Location |
|----------|----------|
| OWASP Top 10 Reference | `docs/owasp-reference/top-10-summary.md` |
| Security Checklist | `docs/checklists/security-review-checklist.md` |
| STRIDE Template | `threat-models/templates/stride-template.md` |
| Completed Threat Model | `threat-models/examples/auth-payment-system-threat-model.md` |
| Lab 1 Answer Key | `exercises/lab1-identification/answer-key.md` |
| Secure Implementations | `src/main/java/com/securelabs/secure/` |

---

## Helpful Copilot Prompts

### Security Analysis
```
Analyze this Java file for OWASP Top 10 vulnerabilities.
For each issue: OWASP category, severity, line number, attack scenario, fix.
```

### Threat Modeling
```
Perform STRIDE analysis for this Spring Boot system.
Identify threats for each category with impact and mitigation.
```

### Secure Refactoring
```
Refactor this code to follow Spring Security best practices.
Add: input validation, authorization, secure logging, parameterized queries.
```

### Code Review
```
Review this Java code against the security checklist.
Flag any violations with severity and recommended fix.
```

---

## Java-Specific Security Patterns

### Password Hashing
```java
// SECURE: Use BCrypt with cost factor >= 12
BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);
String hash = encoder.encode(password);
boolean valid = encoder.matches(input, hash);
```

### SQL Injection Prevention
```java
// SECURE: Use PreparedStatement
String sql = "SELECT * FROM users WHERE email = ?";
PreparedStatement stmt = connection.prepareStatement(sql);
stmt.setString(1, email);
```

### Secure Random
```java
// SECURE: Use SecureRandom for tokens
SecureRandom random = new SecureRandom();
byte[] bytes = new byte[32];
random.nextBytes(bytes);
```

---

## Support

- **Documentation:** See `docs/` directory
- **Reference Code:** See `src/main/java/com/securelabs/secure/` directory
- **Answer Keys:** See exercise directories

---

**Remember:** Security is everyone's responsibility. Use Copilot as a tool, but verify all suggestions.
