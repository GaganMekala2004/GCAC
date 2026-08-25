---
name: java-spring-secure-remediation
description: Reusable secure coding procedures for remediating Java, Spring Boot, Spring Security, Hibernate/JPA, REST API, and Maven/Gradle configuration defects.
---

# Java / Spring Secure Remediation Procedure

1. **Root Cause Identification**:
   - Locate vulnerable Java class at `LocationPath`.
   - Identify flaw (e.g. Spring Security `permitAll()` misconfiguration, SQL injection in JDBC/HQL, unvalidated input, CSRF/CORS weakness).

2. **Minimal Secure Fix**:
   - For Spring Security: Update `SecurityFilterChain` bean to enforce proper authorization (`requestMatchers("/api/admin/**").hasRole("ADMIN")`).
   - For SQL/HQL Injection: Use parameterized named parameters (`TypedQuery`, `JpaRepository` queries).
   - For Input Validation: Apply Jakarta validation annotations (`@NotNull`, `@Size`, `@Pattern`).

3. **Validation**:
   - Add JUnit 5 / Spring Boot Test cases covering secure and unauthorized requests.
