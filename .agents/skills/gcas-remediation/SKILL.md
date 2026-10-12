---
name: gcas-remediation
description: Local bounded vulnerability remediation workflow for GCAC using the 7-stage multi-agent architecture, local CSV input, and Shared Markdown state.
---

# GCAC Vulnerability Remediation Skill

This skill guides local vulnerability remediation across applications using the 7-stage multi-agent governance architecture, local CSV repository (`vulnerability/vulnerabilities.csv`), Shared Markdown reports (`output/<title>_<id>.md`), and full evidence persistence (`remediation-output/<id>/`).

## Target Architecture & Agent Flow

### Orchestrator Engine
- **Role**: Manages workflow, state, sequencing, agent handoffs, retries, error handling, and context passing.
- **Human Approval**: GitHub built-in human approval is required for every command other than read commands.
- **Pillars**: State Management • Decision & Routing • Audit & Logging

### The 7 Stages

1. **Classification Agent**
   - Read vulnerabilities from repository/CSV
   - Classify by severity, CWE, type
   - Assess complexity & exploitability
   - Prioritize remediation strategy

2. **Code Analysis Agent (`</>`)**
   - Locate vulnerable code (file, line)
   - Analyze data flow & call flow
   - Understand context & dependencies
   - Identify root cause (Read-Only)

3. **Remediation Agent (🛠️)**
   - Determine secure fix strategy
   - Generate .NET code changes (patch)
   - Follow best practices & secure coding
   - Prepare change summary
   - Only uses existing remediation and knowledge if not stale

4. **Human Approval Gate (🛡️ Pre-Test Authorization)**
   - Review vulnerability analysis and proposed secure patch
   - Decisions: **✓ Approve** (Proceed to Bench Test) | **✕ Reject** (Rework / Changes Requested routing)

5. **Bench Test (🧪)**
   - Create / update unit tests
   - Cover vulnerable scenario
   - Validate fix with targeted tests
   - Retry on Test Failure loop back to Remediation Agent

6. **Final Human Approval Gate (🛡️ Workflow Exit Sign-off)**
   - Final Human Approval before workflow exit
   - Decisions: **✓ Approve** (Proceed to Hand-off) | **✕ Reject** (Retry & Max rejection loop / Rework)

7. **Final Manual Validations (Non-Agentic)**
   - **Regression Testing**: To be performed by App Owners
   - **Deployment**: Through existing CI/CD Pipeline performed by App Owners

### Shared Foundation
- **Context Store**: Code indexing, embeddings, cache
- **Knowledge Base**: Vulnerability patterns, fix patterns, guidance, regular updates & stale knowledge removal
- **Prompt & Template Library**: Standardized prompts, checklists, templates
- **Tooling & Integrations**: VS Code, GitHub Copilot, .NET CLI, Test Runner
- **Audit & Compliance**: Audit trail, approvals, governance, policies
