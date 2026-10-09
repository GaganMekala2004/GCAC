# AGENT WORKFLOW & LIFECYCLE SPECIFICATION (TARGET POC)

## 1. Multi-Agent Workflow Sequence

```
[Developer] ──► /remediate-vulnerability (Copilot Chat)
                      │
                      ▼
[STEP 1-5] Vulnerability Orchestrator
   ├── Discovers CSV records in vulnerability/*.csv
   ├── Presents vulnerability categories (Developer selects ONE)
   ├── Presents matching findings (Developer selects EXACTLY ONE)
   └── Initializes Shared Markdown: output/<title>_<id>.md
                      │
                      ▼
[STEP 6-7] Code Analysis / RCA Agent (READ-ONLY)
   ├── Traces dataflow & call hierarchy from entry point to execution sink
   ├── Identifies root cause and calculates security blast radius
   └── Appends analysis to ## Code Analysis / RCA Agent in Shared Markdown
                      │
                      ▼
[STEP 8-9] Unit Test Agent (BASELINE ON UNFIXED CODE)
   ├── Discovers repository test framework (xUnit, NUnit, MSTest, JUnit)
   ├── Generates vulnerability-specific security unit tests
   ├── Executes baseline test suite on UNFIXED codebase
   └── Appends baseline evidence to ## Unit Test Agent in Shared Markdown
                      │
                      ▼
[STEP 10] HUMAN APPROVAL GATE (GOVERNANCE GATE — MANDATORY STOP!)
   ├── Developer inspects RCA, proposed fix, and baseline test evidence
   └── Decisions: APPROVE | REQUEST CHANGES | REJECT
   └── NO PRODUCTION CODE MODIFIED BEFORE APPROVAL!
                      │ (Upon APPROVE only)
                      ▼
[STEP 11-12] Remediation Agent
   ├── Applies minimal targeted fix addressing root cause (DotNet, Dependency, Config, Java)
   ├── Captures Git diff patch
   ├── Executes post-fix verification tests
   └── Appends fix & test results to ## Remediation Agent in Shared Markdown
                      │
                      ▼
[STEP 13] Regression Agent
   ├── Executes full existing build and regression test suites
   ├── Isolates pre-existing test failures from remediation regressions
   └── Appends results to ## Regression Agent in Shared Markdown
                      │
                      ▼
[STEP 14] Final Validation Agent (INDEPENDENT REVIEW)
   ├── Skeptical independent verification of code, diff, and all test outputs
   ├── Checks for credential leakage, dangerous calls, and security bypasses
   └── Assigns PASS / FAIL / PARTIAL and Final Confidence Score (0-100) in Shared Markdown
                      │
                      ▼
[STEP 15-16] Documentation Agent (FINAL REPORT & CSV SYNC)
   ├── Finalizes report and execution summary in Shared Markdown
   └── Performs controlled single-row update to the local CSV (SOLE WRITER!)
```

---

## 2. Agent Delegation Matrix

| Stage | Responsible Agent / Gate | Primary Responsibility | Modifies Production Code? | Modifies CSV? | State Modified |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1-5** | **Vulnerability Orchestrator** | Discovers CSVs, guides single finding selection, initializes Shared Markdown | ❌ NO | ❌ NO | Creates `output/<title>_<id>.md` |
| **6-7** | **Code Analysis / RCA Agent** | Dataflow tracing, call flow, root cause analysis, fix design | ❌ NO | ❌ NO | Appends `## Code Analysis / RCA Agent` |
| **8-9** | **Unit Test Agent** | Discovers test framework, runs baseline on unfixed code | ❌ NO (Test only) | ❌ NO | Appends `## Unit Test Agent` |
| **10** | **Human Approval Gate** | **MANDATORY GOVERNANCE GATE (Human Developer)** | — | — | Appends `## Human Approval Gate` |
| **11-12**| **Remediation Agent** | Applies minimal secure code fix, captures diff, runs post-fix tests | ✅ YES (Minimal) | ❌ NO | Appends `## Remediation Agent` |
| **13** | **Regression Agent** | Runs full regression suite, distinguishes pre-existing failures | ❌ NO | ❌ NO | Appends `## Regression Agent` |
| **14** | **Final Validation Agent** | Independent skeptical audit; assigns PASS/FAIL/PARTIAL & confidence score | ❌ NO | ❌ NO | Appends `## Final Validation Agent` |
| **15-16**| **Documentation Agent** | Finalizes Shared Markdown; updates single selected row in local CSV | ❌ NO | ✅ YES (Single row) | Appends `## Documentation Agent`, updates CSV |

---

## 3. Human-in-the-Loop Repositioning

In the target POC architecture:
- Human Approval occurs **AFTER** Root Cause Analysis and Baseline Testing.
- Human Approval occurs **BEFORE** any production code modification.
- Automated remediation **CANNOT** edit source code without an explicit `APPROVED` governance record in the Shared Markdown report.
