# Lab Action Guide - Java

Follow these lean steps using GitHub Copilot for all work. Each lab builds on the previous—complete them in order.

## Quick Reference

| Lab | Duration | Primary Actions | Copilot Tools |
| --- | --- | --- | --- |
| Setup | 5 min | `#runInTerminal mvn clean compile` | Terminal commands |
| 1 | 30 min | Analyze `src/main/java/**/vulnerable/**` | Select **Security Vulnerability Hunter** mode, or use `/find-vulnerabilities` |
| 2 | 25 min | STRIDE analysis, Mermaid architecture | Select **Threat Modeler** mode, or use `/generate-threat-model` |
| 3 | 35 min | Refactor vulnerable code, run tests | Select **Secure Code Reviewer** mode, or use `/fix-vulnerability` |
| Verify | 5 min | `#runInTerminal mvn clean package` | Select **OWASP Expert** mode for final review |

## Copilot Customizations

This lab includes expert-level GitHub Copilot customizations to accelerate your security work.

### How to Use Agents/Chatmodes

**Agents and chatmodes are selected from the Copilot Chat mode dropdown**, not referenced with `@` syntax.

1. Open Copilot Chat (`Ctrl+Shift+I` / `Cmd+Shift+I`)
2. Click the **mode selector dropdown** at the top of the chat panel
3. Select the desired agent (e.g., "Security Vulnerability Hunter")
4. Type your prompt - the agent's expertise will guide the response

### Available Agents

| Agent | Purpose | Best For |
|-------|---------|----------|
| **Security Vulnerability Hunter** | Systematic OWASP Top 10 vulnerability discovery | Lab 1 - Finding vulnerabilities |
| **Secure Code Reviewer** | Validates security fixes against best practices | Lab 3 - Reviewing your fixes |
| **Threat Modeler** | STRIDE methodology expert | Lab 2 - Creating threat models |
| **OWASP Expert** | OWASP category reference and CWE mapping | All labs - Understanding vulnerabilities |

### Prompts (Invoke with `/prompt-name`)

Prompts can be invoked directly by typing `/` followed by the prompt name:

| Prompt | How to Use | Output |
|--------|------------|--------|
| `/find-vulnerabilities` | Type `/find-vulnerabilities` then add file context | Vulnerability report with severity, CWE, attack scenarios |
| `/fix-vulnerability` | Type `/fix-vulnerability` then describe the issue | Fixed code with explanation and test case |
| `/generate-threat-model` | Type `/generate-threat-model` then add system context | Complete threat model document with Mermaid diagram |

### Auto-Applied Instructions

The `.github/instructions/java-security.instructions.md` file automatically applies Java security coding standards to all `*.java` files. Copilot will reference these patterns when suggesting code.

## Setup – Environment Preparation

- Copilot Chat: `#runInTerminal mvn clean compile`
- Copilot Chat: `#runInTerminal mvn test`
- Verify no build errors before proceeding
- Open `README.md` to review lab structure

## Lab 1 – Vulnerability Identification (30 min)

### Phase 1: Reconnaissance (10 min)

**Option A: Using the Security Vulnerability Hunter Agent**
1. Open Copilot Chat
2. Select **Security Vulnerability Hunter** from the mode dropdown
3. Type:
```
Analyze all files in src/main/java/com/securelabs/vulnerable/
and create an attack surface map identifying entry points and data flows.
```

**Option B: Manual Approach**
- Copilot Chat: `@workspace List all Java files in src/main/java/com/securelabs/vulnerable/ and identify which OWASP Top 10 categories each file likely contains`
- Review the file list and create mental map of attack surface
- Start with `#file:src/main/java/com/securelabs/vulnerable/auth/AuthController.java`

### Phase 2: Deep Analysis (15 min)

**Option A: Using the Find Vulnerabilities Prompt**
```
/find-vulnerabilities

#file:src/main/java/com/securelabs/vulnerable/auth/AuthController.java
```
Repeat for each file in the vulnerable directory.

**Option B: Using the Agent for Comprehensive Scan**
1. Select **Security Vulnerability Hunter** from mode dropdown
2. Type:
```
Perform a complete OWASP Top 10 security audit of:
- AuthController.java
- PaymentHandler.java
- UserRepository.java
- ResourceController.java
- TokenManager.java
- ModernApiHandler.java

Provide findings in a table format with OWASP category, severity, and line numbers.
```

**Option C: Manual Analysis**
- For each vulnerable file, use this prompt pattern:
```
#file:src/main/java/com/securelabs/vulnerable/auth/AuthController.java

Analyze this Java file for OWASP Top 10 vulnerabilities.
For each issue found:
1. OWASP category (A01-A10)
2. Severity (Critical/High/Medium/Low)
3. Line number(s)
4. Attack scenario
5. Recommended fix
```

**Need Help with Categories?**
1. Select **OWASP Expert** from mode dropdown
2. Ask: `What is the difference between A01 Broken Access Control and A07 Authentication Failures?`

### Phase 3: Documentation (5 min)
- Copilot Chat: Generate a vulnerability summary table
- Compare findings against `#file:exercises/lab1-identification/answer-key.md`
- Target: Identify at least 40 of 62 documented vulnerabilities

## Lab 2 – Threat Modeling (25 min)

### Phase 1: Architecture (5 min)

**Option A: Using the Threat Modeler Agent**
1. Select **Threat Modeler** from mode dropdown
2. Type:
```
Create an architecture diagram for the Spring Boot payment system in this repository.
Identify all components, data flows, and trust boundaries.
Output as a Mermaid flowchart.
```

**Option B: Using the Generate Threat Model Prompt**
```
/generate-threat-model

For the authentication and payment system in src/main/java/com/securelabs/
```

**Option C: Manual Approach**
- Copilot Chat:
```
Generate a Mermaid diagram for a Spring Boot payment system with:
- AuthController (login, registration)
- PaymentHandler (payments, refunds, webhooks)
- ResourceController (files, external resources)
- SessionManager, TokenManager, UserRepository

Include trust boundaries between:
1. Internet and API gateway
2. API gateway and Spring controllers
3. Controllers and database/external services

Use Mermaid flowchart syntax with subgraphs for trust boundaries.
```

### Phase 2: STRIDE Analysis (15 min)

**Option A: Using the Threat Modeler Agent**
1. Select **Threat Modeler** from mode dropdown
2. Type:
```
Perform a complete STRIDE analysis for the payment system.
For each STRIDE category, identify at least 3 threats with:
- Attack description
- Affected component
- Impact rating (Critical/High/Medium/Low)
- Likelihood rating
- Recommended mitigation
```

**Option B: Manual STRIDE Analysis**
- Copilot Chat: Perform STRIDE analysis using this sequence:
```
For the Spring Boot auth/payment system, perform STRIDE analysis.

SPOOFING: How can attackers impersonate users or the system?
TAMPERING: What data can be modified maliciously?
REPUDIATION: What actions can users deny performing?
INFORMATION DISCLOSURE: What sensitive data could be exposed?
DENIAL OF SERVICE: What resources can be exhausted?
ELEVATION OF PRIVILEGE: How can users gain unauthorized access?

For each threat: describe attack, impact (H/M/L), and mitigation.
```

**Reference Materials:**
- Template: `#file:threat-models/templates/stride-template.md`
- Example: `#file:threat-models/examples/auth-payment-system-threat-model.md`

### Phase 3: Prioritization (5 min)

**Using the Agent:**
1. Select **Threat Modeler** from mode dropdown
2. Type:
```
Prioritize the identified threats by:
1. Business impact (financial, reputational, compliance)
2. Exploitability (skill required, access needed)
3. Existing mitigations in the codebase

Recommend the top 5 threats to address first.
```

- Save threat model to `threat-models/my-threat-model.md`
- Compare against `#file:threat-models/examples/auth-payment-system-threat-model.md`

## Lab 3 – Secure Implementation (35 min)

### Before You Start: Understanding Fix Patterns

**Ask the OWASP Expert for guidance:**
1. Select **OWASP Expert** from mode dropdown
2. Ask:
```
What are the secure coding patterns for:
1. Password hashing in Java
2. SQL injection prevention
3. SSRF protection
4. Secure session management
```

### Task 1: Secure Authentication (10 min)

**Option A: Using the Fix Vulnerability Prompt**
```
/fix-vulnerability

SQL Injection in AuthController.java login method

#file:src/main/java/com/securelabs/vulnerable/auth/AuthController.java
```
Then repeat for each vulnerability type.

**Option B: Comprehensive Fix Request**
- Copilot Chat:
```
#file:src/main/java/com/securelabs/vulnerable/auth/AuthController.java

Refactor this Spring Boot authentication controller to fix:
1. Add password hashing using BCryptPasswordEncoder (cost factor 12)
2. Implement account lockout after 5 failed attempts for 30 minutes
3. Generate secure session tokens using SecureRandom
4. Remove passwords from logs and responses
5. Use generic error messages to prevent user enumeration
6. Add httpOnly, Secure, and SameSite flags to cookies

Reference: #file:src/main/java/com/securelabs/secure/auth/SecureAuthController.java
```

**Verify Your Fix:**
1. Select **Secure Code Reviewer** from mode dropdown
2. Ask:
```
Review my changes to AuthController.java.
Verify all authentication vulnerabilities are properly fixed.
```

- Apply changes using Copilot's "Apply in Editor"
- Verify with: `#runInTerminal mvn compile`

### Task 2: Secure Payment Processing (10 min)

**Option A: Using the Fix Vulnerability Prompt**
```
/fix-vulnerability

Missing webhook signature verification in PaymentHandler.java

#file:src/main/java/com/securelabs/vulnerable/api/PaymentHandler.java
```

**Option B: Comprehensive Fix Request**
- Copilot Chat:
```
#file:src/main/java/com/securelabs/vulnerable/api/PaymentHandler.java

Fix these security issues:
1. INPUT VALIDATION: Amount (positive, max $1M, 2 decimals), Currency (whitelist USD/EUR/GBP)
2. AUTHORIZATION: Verify transaction ownership before refund
3. LOGGING: Remove all credit card data from logs
4. WEBHOOK: Add HMAC signature verification with timestamp validation

Reference: #file:src/main/java/com/securelabs/secure/api/SecurePaymentHandler.java
```

**Verify Your Fix:**
1. Select **Secure Code Reviewer** from mode dropdown
2. Ask:
```
Check PaymentHandler.java for:
- Proper input validation
- HMAC webhook verification
- No sensitive data in logs
```

### Task 3: Fix SQL Injection (8 min)

**Option A: Using the Fix Vulnerability Prompt**
```
/fix-vulnerability

SQL Injection via string concatenation in UserRepository.java

#file:src/main/java/com/securelabs/vulnerable/data/UserRepository.java
```

**Option B: Comprehensive Fix Request**
- Copilot Chat:
```
#file:src/main/java/com/securelabs/vulnerable/data/UserRepository.java

Convert all SQL queries to use PreparedStatement:
1. findByEmail - parameterized query
2. searchUsers - parameterized LIKE with validated ORDER BY whitelist
3. findByQuery - whitelist allowed fields
4. exportUsers - remove Runtime.exec command injection
5. getUserAvatar - add path traversal protection

Reference: #file:src/main/java/com/securelabs/secure/data/SecureUserRepository.java
```

### Task 4: Fix SSRF and Access Control (7 min)

**Option A: Using the Fix Vulnerability Prompt**
```
/fix-vulnerability

SSRF via unvalidated URL fetching in ResourceController.java

#file:src/main/java/com/securelabs/vulnerable/api/ResourceController.java
```

**Option B: Comprehensive Fix Request**
- Copilot Chat:
```
#file:src/main/java/com/securelabs/vulnerable/api/ResourceController.java

Fix critical vulnerabilities:
1. SSRF: Add URL allowlist, block internal IPs (10.x, 172.16.x, 192.168.x, 169.254.x), HTTPS only
2. AUTHORIZATION: Add @PreAuthorize or manual auth check, verify resource ownership
3. OPEN REDIRECT: Validate redirect URLs against allowlist
4. CORS: Replace @CrossOrigin(origins = "*") with specific allowed origins

Reference: #file:src/main/java/com/securelabs/secure/api/SecureResourceController.java
```

### Task 5: Fix Java 17+ Vulnerabilities (Bonus)

```
/fix-vulnerability

HttpClient SSRF in ModernApiHandler.java

#file:src/main/java/com/securelabs/vulnerable/api/ModernApiHandler.java
```

Then select **Secure Code Reviewer** mode and ask:
```
Review ModernApiHandler.java for Java 17+ specific vulnerabilities:
- HttpClient SSRF
- Parallel stream race conditions
- Text block injection
- Record toString() data exposure
```

## Final Verification

### Build Verification
- Copilot Chat: `#runInTerminal mvn clean compile`
- Copilot Chat: `#runInTerminal mvn test`

### Security Review with Agents

**Comprehensive Security Audit:**
1. Select **Secure Code Reviewer** from mode dropdown
2. Ask:
```
Perform a final security review of all modified files in src/main/java/com/securelabs/vulnerable/

For each file confirm:
1. Original vulnerabilities are fixed
2. No new vulnerabilities introduced
3. Code follows Spring Security best practices
4. Proper error handling without information disclosure
```

**Verify Against OWASP Standards:**
1. Select **OWASP Expert** from mode dropdown
2. Ask:
```
Review the implemented fixes against OWASP ASVS (Application Security Verification Standard).
Are there any gaps in our security controls?
```

**Re-run Vulnerability Scan:**
1. Select **Security Vulnerability Hunter** from mode dropdown
2. Ask:
```
Re-scan all modified files.
Compare against the original 62 vulnerabilities - how many remain?
```

## Success Checklist

| Category | Requirements | Verified |
|----------|--------------|----------|
| Lab 1 | Identified ≥40 of 62 vulnerabilities with OWASP categories | ☐ |
| Lab 2 | Created STRIDE threat model with ≥12 threats | ☐ |
| Authentication | BCrypt, lockout, secure tokens implemented | ☐ |
| Input Validation | Amount, currency, card validation added | ☐ |
| Authorization | Ownership checks, role verification added | ☐ |
| Injection | PreparedStatement, no string concatenation | ☐ |
| SSRF | URL allowlist, internal IP blocking | ☐ |
| Logging | No sensitive data in logs | ☐ |
| Build | `mvn compile` passes | ☐ |
| Tests | `mvn test` passes | ☐ |

## Copilot Prompt Patterns

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
Add: input validation, @PreAuthorize, secure logging, PreparedStatement.
```

### Code Review
```
Review this Java code against the security checklist.
Flag any violations with severity and recommended fix.
```

## Key Resources

### Documentation

| Resource | Location |
|----------|----------|
| OWASP Top 10 Reference | `docs/owasp-reference/top-10-summary.md` |
| Security Checklist | `docs/checklists/security-review-checklist.md` |
| STRIDE Template | `threat-models/templates/stride-template.md` |
| Completed Threat Model | `threat-models/examples/auth-payment-system-threat-model.md` |
| Lab 1 Answer Key | `exercises/lab1-identification/answer-key.md` |
| Secure Implementations | `src/main/java/com/securelabs/secure/` |

### Copilot Customizations

| Type | Name | Location |
|------|------|----------|
| Agent | Security Vulnerability Hunter | `.github/agents/security-vulnerability-hunter.agent.md` |
| Agent | Secure Code Reviewer | `.github/agents/secure-code-reviewer.agent.md` |
| Agent | Threat Modeler | `.github/agents/threat-modeler.agent.md` |
| Agent | OWASP Expert | `.github/agents/owasp-expert.agent.md` |
| Prompt | Find Vulnerabilities | `.github/prompts/find-vulnerabilities.prompt.md` |
| Prompt | Fix Vulnerability | `.github/prompts/fix-vulnerability.prompt.md` |
| Prompt | Generate Threat Model | `.github/prompts/generate-threat-model.prompt.md` |
| Instructions | Java Security Standards | `.github/instructions/java-security.instructions.md` |

### Chatmodes (Legacy/Backwards Compatible)

For VS Code users with older Copilot versions, equivalent chatmodes are available in `.github/chatmodes/`.

## Reminder

- **All work via Copilot**: Use `#runInTerminal` for commands, `#file:` for context, `@workspace` for project-wide queries
- **Select Agents from dropdown**: Click the mode selector in Copilot Chat to choose an agent
- **Use Prompts with `/`**: Type `/prompt-name` to invoke custom prompts
- **No manual typing**: Let Copilot generate all code and terminal commands
- **Verify suggestions**: Security is everyone's responsibility—review Copilot output before applying
