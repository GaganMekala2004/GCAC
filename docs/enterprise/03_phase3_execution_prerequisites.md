# Phase 3 Execution Prerequisites & Cross-Platform Assessment

**Document ID:** GCAC-ENT-PH3-PREREQ  
**Assessment Date:** 2026-11-11  
**Target Environment Audited:** Local Windows Workstation (`Windows_NT 10.0.26200` / `win32` / `x64`)

## 1. Live Environment Discovery Summary

Empirical discovery executed via `extension/sandbox/environmentDiscovery.js` (`discoverEnvironment`) and `EnvironmentDiscoveryService`:

| Component | Observed Status | Observed Details |
| :--- | :--- | :--- |
| Operating System / Arch | Windows 11 (`win32` / `x64`, `10.0.26200`) | Native host execution without WSL2 |
| WSL2 | `NOT INSTALLED` | `"The Windows Subsystem for Linux is not installed."` |
| Docker CLI / Daemon | `NOT INSTALLED` | Not in `PATH` or `C:\Program Files\Docker\Docker\resources\bin\docker.exe` |
| Podman CLI / Machine | `NOT INSTALLED` | Not in `PATH` |
| Sandbox Readiness | **`SANDBOX_UNAVAILABLE`** | `sandboxAvailable = false`; governed builds/tests fail closed (`BLOCKED`) |
| .NET SDK | `INSTALLED` (`9.0.317`) | No `global.json`; solution projects target `net9.0` |
| Node.js / npm | Node `v24.18.0`, npm `11.16.0` | `npm.cmd` requires shell-disabled handling on Node 24 Windows |
| Java / Maven | `NOT INSTALLED` | `java`, `javac`, and `mvn` absent from `PATH` |
| Git | `INSTALLED` (`2.55.0.windows.3`) | Used for Phase 2 worktree isolation |
| Scanners / External SBOM CLIs | `NOT INSTALLED` | `codeql`, `syft`, `trivy`, `cdxgen`, `cyclonedx`, `dotnet-cyclonedx` absent |
| Repository Lockfiles | `PRESENT` (`packages.lock.json`, `package-lock.json`) | Root `package-lock.json` and 7 project `packages.lock.json` files generated offline; `Directory.Packages.props` omitted to preserve `<PackageReference Version="..." />` SBOM parsing |

---

## 2. Exact Prerequisites Required to Enable Local Container Execution

Do **NOT** auto-install container infrastructure from the extension. An administrator or developer must explicitly provision:

1. **Windows 10/11 Hosts (`win32`):**
   - Enable WSL2 (`wsl --install`) and reboot.
   - Install **Docker Desktop** configured explicitly in **Linux containers mode** (`OSType = linux`, Windows containers mode is rejected) OR **Podman v4+** with an initialized Linux Podman machine (`podman machine init && podman machine start`).
   - Verify `docker info --format "{{json .}}"` returns `"OSType":"linux"`.
2. **Linux Hosts (`linux`):**
   - Install **Podman v4+ (rootless preferred)** or **Docker Engine** with non-root user namespace support (`seccomp`, AppArmor/SELinux enabled).
   - Start `docker` or rootless `podman` socket and ensure daemon connectivity.
3. **macOS Hosts (`darwin`):**
   - Install Docker Desktop / Colima / Podman machine (`amd64` or `arm64` matching container `--platform`).
4. **Toolchain Images & Offline Package Caches (Mandatory for `NO_NETWORK` execution):**
   - Pull approved Linux SDK images from your enterprise registry, replace template placeholder `@sha256:...` digests in `extension/config/approved-toolchain-profiles.json` (e.g., via `node scripts/verify-phase3-sandbox.js --pin-from-local-images`), and verify `digestStatus` updates from `TEMPLATE_PLACEHOLDER` to `VERIFIED_IMAGE_DIGEST` with recomputed `profileSha256`.
   - Keep images pre-pulled in local daemon storage (extension blocks unapproved `docker pull` at runtime by default when `requirePrePulledImage = true`).
   - Run `node scripts/verify-phase3-sandbox.js --smoke-test` to verify live `--network=none` container execution (`G3-06`).
   - Lockfiles (`packages.lock.json` across solution projects and `package-lock.json` at root) are now committed; pre-warm per-application offline caches (`.nuget`, `.m2`, `npm`) before isolated `--network=none` builds.

---

## 3. Cross-Platform Isolation & Boundary Assessment

| Platform | Container Mechanism | Rootless / UserNS Support | Limitations |
| :--- | :--- | :--- | :--- |
| **Linux** (`x64`/`arm64`) | Native Docker or Rootless Podman | Native user namespaces + cgroups v2 + seccomp | Containers share host Linux kernel |
| **Windows** (`x64`/`arm64`) | Docker Desktop WSL2 / Podman Machine | Managed inside WSL2 utility VM Linux kernel | No native Windows sandbox without WSL2; Windows containers not supported |
| **macOS** (`x64`/`arm64`) | Docker Desktop / Podman / Lima VM | Managed inside Linux VM | Apple silicon requires `linux/arm64` digest matching or explicit emulation policy |

### Architectural Boundary Disclosure
- A local container is **process/filesystem/network namespace isolation sharing a kernel** (host Linux kernel on Linux, WSL2/VM kernel on Windows/macOS).
- For untrusted multi-tenant or high-assurance workloads requiring hardware virtualization boundaries, use **dedicated ephemeral CI/VM runners** via `EphemeralCiRunnerBackend` (fail-closed adapter stub implemented; no remote service added without authorization).

---

## 4. .NET 9 (STS) vs LTS Support Assessment (Non-Mutating)

- All 7 existing `.csproj` files (`Domain`, `Persistence`, `Excel`, `Repository`, `Cli`, `VulnerabilityDataMcp`, `Tests`) currently target **`net9.0` (Standard Term Support)** and compile/run cleanly under installed SDK `9.0.317`.
- Per Phase 3 guidelines, frameworks were **not** silently downgraded or rewritten.
- **Enterprise Recommendation:** Schedule a deliberate migration to **`.NET 8 LTS`** (or **`.NET 10 LTS`**) with updated `Directory.Packages.props` and `global.json` pinning before long-term enterprise production rollout.

---

## 5. Future Toolchain Adapters (Documented, Blocked in Phase 3)

The following build stacks remain explicitly unapproved and are fail-closed blocked (`UNAPPROVED_TOOLCHAIN_STACK`) in `ToolchainProfileRegistry` until validated offline profiles/fixtures are introduced:
- **Gradle** (`build.gradle`, `build.gradle.kts`) — `FUTURE_ADAPTER`
- **Apache Ant** (`build.xml`) — `FUTURE_ADAPTER`
- **Python** (`requirements.txt`, `pyproject.toml`) — `FUTURE_ADAPTER`

