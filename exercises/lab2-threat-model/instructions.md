# Lab 2: Threat Modeling with GitHub Copilot (Java)

**Duration:** 25 minutes
**Objective:** Create a STRIDE threat model for the authentication and payment system analyzed in Lab 1.

---

## Important: Copilot-Only Workflow

Complete all work using GitHub Copilot Chat and inline suggestions.

---

## System Context

You are threat modeling the **same system** from Lab 1:
- AuthController (login, registration, password reset)
- PaymentHandler (process payments, refunds, webhooks)
- ResourceController (file access, external fetching)
- Session & Token Management

Reference architecture: `threat-models/examples/auth-payment-system-threat-model.md`

---

## Step-by-Step Instructions

### Step 1: Generate Architecture Diagram (5 min)

**Copilot Chat Prompt:**
```
Generate a Mermaid flowchart diagram for a Spring Boot payment system with:
- AuthController (login, registration)
- PaymentHandler (payments, refunds, webhooks)
- ResourceController (files, external resources)
- SessionManager
- TokenManager (JWT)
- UserRepository (database)

Include trust boundaries as subgraphs between:
1. Internet and API gateway
2. API gateway and Spring controllers
3. Controllers and database/external services

Use Mermaid flowchart syntax with subgraphs for trust boundaries.
```

### Step 2: Identify Trust Boundaries (3 min)

**Copilot Chat Prompt:**
```
For the Spring Boot auth/payment system, identify:
1. All trust boundaries
2. What data crosses each boundary
3. What security controls should exist at each boundary

Consider: network boundaries, authentication boundaries,
authorization boundaries, Spring Security filters.
```

### Step 3: STRIDE Analysis - Spoofing & Tampering (5 min)

**Copilot Chat Prompt:**
```
Perform STRIDE analysis for the Spring Boot auth/payment system.

For SPOOFING threats, identify:
- How can attackers impersonate legitimate users?
- How can attackers impersonate the system?
- What authentication weaknesses exist?

For TAMPERING threats, identify:
- What data can be modified in transit?
- What data can be modified at rest?
- How can business logic be manipulated?

For each threat: describe attack, impact (High/Medium/Low),
and mitigation.
```

### Step 4: STRIDE Analysis - Repudiation & Info Disclosure (5 min)

**Copilot Chat Prompt:**
```
Continue STRIDE analysis:

For REPUDIATION threats:
- What actions can users deny performing?
- What audit logging gaps exist?
- How can attackers cover their tracks?

For INFORMATION DISCLOSURE:
- What sensitive data could be exposed?
- Through which channels (logs, errors, responses)?
- What PII/PCI data is at risk?

For each: threat description, impact, mitigation.
```

### Step 5: STRIDE Analysis - DoS & Elevation (4 min)

**Copilot Chat Prompt:**
```
Complete STRIDE analysis:

For DENIAL OF SERVICE:
- What resources can be exhausted?
- What rate limiting gaps exist?
- How can the system be overwhelmed?

For ELEVATION OF PRIVILEGE:
- How can users gain unauthorized access?
- What role escalation paths exist?
- How can admin functions be accessed?

For each: threat, impact, mitigation.
```

### Step 6: Prioritize Threats (3 min)

**Copilot Chat Prompt:**
```
Based on the STRIDE analysis for the Spring Boot auth/payment system,
rank the top 5 most critical threats.

For each:
1. Threat ID and name
2. Why it's critical (business impact)
3. Recommended mitigation
4. Implementation complexity (Easy/Medium/Hard)

Consider: financial impact, data breach potential,
regulatory compliance (PCI-DSS).
```

---

## Deliverable Template

Create a new file using Copilot:

**Copilot Chat Prompt:**
```
Create a threat model document for the Spring Boot auth/payment system.
Use the STRIDE template from threat-models/templates/stride-template.md
Fill in the sections based on our analysis.

Include:
- System overview with Mermaid architecture diagram
- Trust boundaries
- At least 2 threats per STRIDE category
- Top 5 priority threats
- Recommended mitigations with owners
```

Save to: `threat-models/my-threat-model.md`

---

## Validation

Compare your threat model with:
`threat-models/examples/auth-payment-system-threat-model.md`

**Target:** Identify at least 12 threats (2 per STRIDE category).

---

## STRIDE Quick Reference

| Letter | Category | Key Question |
|--------|----------|--------------|
| S | Spoofing | Can someone pretend to be someone else? |
| T | Tampering | Can data be modified maliciously? |
| R | Repudiation | Can actions be denied? |
| I | Information Disclosure | Can sensitive data be exposed? |
| D | Denial of Service | Can the system be made unavailable? |
| E | Elevation of Privilege | Can users gain unauthorized access? |
