---
name: dependency-remediation
description: Procedures for safely updating third-party NuGet, Maven, or Gradle dependencies to patch vulnerabilities while avoiding breaking changes.
---

# Dependency Remediation Procedure

1. **Locate Dependency Declaration**:
   - For .NET: Inspect `*.csproj`, `Directory.Packages.props`, `packages.lock.json`.
   - For Java: Inspect `pom.xml`, `build.gradle`, `build.gradle.kts`.

2. **Evaluate Version Strategy**:
   - Determine smallest safe version upgrade that satisfies `FixedVersion` and resolves CVE.
   - Avoid "update everything to latest" broad upgrades. Prefer targeted dependency updates.

3. **Modify Configuration & Restore**:
   - Update version string in package manifest.
   - Execute package restore (`dotnet restore`, `mvn dependency:resolve`, `./gradlew dependencies`).
