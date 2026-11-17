# GCAC Platform .NET 10 Migration Assessment & Implementation Report

**Document ID**: `GCAC-DOC-PH3-06-MIGRATION`  
**Classification**: Enterprise Architecture & Engineering  
**Evaluator**: Principal .NET Engineer & DevSecOps Architect  
**Date**: November 15, 2026  
**Status**: COMPATIBLE & FULLY IMPLEMENTED  

---

## 1. Executive Summary

This report evaluates and implements the platform migration of the GCAC repository from `.NET 9.0` (Standard Term Support - STS) to `.NET 10.0` (Long Term Support - LTS). 

The existing solution (`VulnerabilityRemediation.sln`) contains seven C# projects targeting `net9.0`. However, the current development and execution host (macOS Apple Silicon ARM64) is equipped with `.NET SDK 10.0.403` and `.NET Core Runtime 10.0.14`. Under `.NET 9`, host execution of tests and the STDIO Model Context Protocol (MCP) server `VulnerabilityDataMcp.dll` failed with fatal exit code `150` due to the absence of the `Microsoft.NETCore.App 9.0.0` runtime.

All seven projects, their transitive NuGet dependencies, lockfiles, and test suites were audited, upgraded to `net10.0`, rebuilt, and verified. 100% of automated tests (66/66) passed cleanly with zero compilation errors.

---

## 2. Environment Discrepancy & Migration Driver

### 2.1 Host Environment Discovery
* **Operating System**: macOS Darwin `25.6.0` (Apple Silicon ARM64)
* **Installed .NET SDK**: `10.0.403` (`/opt/homebrew/Cellar/dotnet/10.0.403/libexec/sdk/10.0.403/`)
* **Installed .NET Runtimes**:
  * `Microsoft.AspNetCore.App 10.0.14`
  * `Microsoft.NETCore.App 10.0.14`
* **Installed .NET 9 Runtimes**: **None** (`9.0.x` absent)

### 2.2 Symptoms of Target Framework Mismatch Under .NET 9
1. **MCP Server Startup Crash (Exit 150)**:
   ```
   You must install or update .NET to run this application.
   App: mcp/VulnerabilityDataMcp/bin/Debug/net9.0/VulnerabilityDataMcp.dll
   Framework: 'Microsoft.NETCore.App', version '9.0.0' (arm64)
   The following frameworks were found: 10.0.14 at [/opt/homebrew/Cellar/dotnet/10.0.403/libexec/shared/Microsoft.NETCore.App]
   ```
2. **xUnit Test Execution Failure**:
   ```
   Testhost process for source(s) 'tests/VulnerabilityRemediation.Tests/.../VulnerabilityRemediation.Tests.dll' exited with error: 
   You must install or update .NET to run this application. Framework: 'Microsoft.NETCore.App', version '9.0.0' (arm64).
   ```
3. **Container Air-Gap Build Blocker**:
   In the `mcr.microsoft.com/dotnet/sdk:10.0` Docker sandbox without network egress (`--network none`), attempting to build `net9.0` targets resulted in:
   ```
   error NU1301: Unable to load the service index for source https://api.nuget.org/v3/index.json.
   ```
   Because the .NET 10 SDK container image only bundles the `10.0.x` targeting pack, targeting `net9.0` required downloading external targeting packs over the blocked network.

---

## 3. Seven .NET Projects Inspection & Dependency Audit

The seven projects comprising `VulnerabilityRemediation.sln` were audited:

| Project Path | Output Type | Target Framework | Key Dependencies | net10.0 Compatibility |
| :--- | :--- | :--- | :--- | :--- |
| `src/VulnerabilityRemediation.Domain` | Classlib | `net10.0` | None (Pure C# domain model) | 100% Compatible |
| `src/VulnerabilityRemediation.Persistence` | Classlib | `net10.0` | `Microsoft.Data.Sqlite (9.0.2)` | 100% Compatible (runs on 10.0 runtime) |
| `src/VulnerabilityRemediation.Repository` | Classlib | `net10.0` | Project references to Domain & Persistence | 100% Compatible |
| `src/VulnerabilityRemediation.Excel` | Classlib | `net10.0` | `ClosedXML (0.104.2)` | 100% Compatible |
| `src/VulnerabilityRemediation.Cli` | Exe | `net10.0` | Project references to all libraries | 100% Compatible |
| `mcp/VulnerabilityDataMcp` | Exe | `net10.0` | STDIO JSON-RPC 2.0 Server | 100% Compatible |
| `tests/VulnerabilityRemediation.Tests` | Test | `net10.0` | `Microsoft.NET.Test.Sdk (17.11.1)`, `xunit (2.9.2)`, `xunit.runner.visualstudio (2.8.2)` | 100% Compatible |

### Dependency Analysis:
* **ClosedXML 0.104.2**: Targets `netstandard2.0`, `netstandard2.1`, and `net8.0`. Fully compatible with .NET 10 runtime without breaking API changes.
* **Microsoft.Data.Sqlite 9.0.2**: Targets `net9.0` and `netstandard2.0`. Backward-compatible and functional on .NET 10.
* **xUnit 2.9.2 & Test SDK 17.11.1**: Discovers and executes tests on the `net10.0` testhost without deprecation warnings.

---

## 4. Changes Implemented

### 4.1 Project Files (`*.csproj`)
Updated `<TargetFramework>` from `net9.0` to `net10.0` in:
1. `src/VulnerabilityRemediation.Domain/VulnerabilityRemediation.Domain.csproj`
2. `src/VulnerabilityRemediation.Persistence/VulnerabilityRemediation.Persistence.csproj`
3. `src/VulnerabilityRemediation.Repository/VulnerabilityRemediation.Repository.csproj`
4. `src/VulnerabilityRemediation.Excel/VulnerabilityRemediation.Excel.csproj`
5. `src/VulnerabilityRemediation.Cli/VulnerabilityRemediation.Cli.csproj`
6. `mcp/VulnerabilityDataMcp/VulnerabilityDataMcp.csproj`
7. `tests/VulnerabilityRemediation.Tests/VulnerabilityRemediation.Tests.csproj`

### 4.2 Toolchain Registry & Profile Resolvers
Updated toolchain framework detection in both C# and JavaScript:
* **`src/VulnerabilityRemediation.Repository/Sandbox/ToolchainProfileRegistry.cs`**:
  * Added `sdkVer.StartsWith("10.")` check in `global.json` parsing.
  * Added `hasNet10` check mapping to approved profile `dotnet-10.0-lts`.
  * Updated exception message to declare `net8.0`, `net9.0`, and `net10.0` approved.
* **`extension/sandbox/toolchainProfiles.js`**:
  * Added `/^10\./.test(requestedDotnetSdk)` returning `dotnet-10.0-lts`.
  * Added `hasNet10` check returning `dotnet-10.0-lts`.

### 4.3 Copilot & VS Code MCP Integration Configurations
Updated the precompiled binary paths for the STDIO MCP server from `net9.0` to `net10.0`:
* **`.vscode/mcp.json`**:
  `"${workspaceFolder}/mcp/VulnerabilityDataMcp/bin/Debug/net10.0/VulnerabilityDataMcp.dll"`
* **`.agents/mcp_config.json`**:
  `"${workspaceFolder}/mcp/VulnerabilityDataMcp/bin/Debug/net10.0/VulnerabilityDataMcp.dll"`

### 4.4 Lockfile Preservation
Ran `dotnet restore VulnerabilityRemediation.sln --use-lock-file` to generate valid `net10.0` lockfile sections across all projects while preserving strict deterministic restore capability.

---

## 5. Verification Evidence

### 5.1 Solution Compilation
```bash
dotnet build VulnerabilityRemediation.sln --no-restore
```
**Result**: Build Succeeded (`0 Error(s)`, `5 Advisory Warning(s)` on transitive SQLite component). All 7 projects compiled successfully.

### 5.2 Automated .NET Test Suite
```bash
dotnet test VulnerabilityRemediation.sln --no-restore
```
**Output**:
```
Test run for VulnerabilityRemediation.Tests.dll (.NETCoreApp,Version=v10.0)
A total of 1 test files matched the specified pattern.

Passed!  - Failed: 0, Passed: 66, Skipped: 0, Total: 66, Duration: 19 s - VulnerabilityRemediation.Tests.dll (net10.0)
```
**Result**: **66 / 66 tests PASSED**.

### 5.3 Live MCP Server JSON-RPC Verification
Executed JSON-RPC 2.0 `initialize` command against the new `net10.0` build:
```bash
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}' | dotnet mcp/VulnerabilityDataMcp/bin/Debug/net10.0/VulnerabilityDataMcp.dll
```
**Output**:
```json
{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"serverInfo":{"name":"VulnerabilityDataMcp","version":"2.0.0"}}}
```
**Result**: Exit code `0`. Instantaneous cold-start response with zero runtime errors.

---

## 6. Separation of Platform Runtime from Target Repository Analysis

It is critical to distinguish between:
1. **The GCAC Platform Runtime**: The VS Code extension, MCP server, and remediation agent test harness, which now run on `.NET 10 LTS`.
2. **External User Repositories**: Client repositories submitted for scanning and remediation. 

External repositories targeting `net8.0` or `net9.0` are handled independently:
* If a target repository specifies `<TargetFramework>net9.0</TargetFramework>`, GCAC's `resolveProfileForRepository()` resolves to `dotnet-9.0-sts`.
* Because `dotnet-9.0-sts` is pinned to a template digest and not present locally, GCAC fails closed with an honest, explicit `IMAGE_NOT_PRE_PULLED` / `TEMPLATE_DIGEST_UNPINNED` error.
* GCAC **does not** force `.NET 10` onto external projects and **does not** silently fall back to host execution.
