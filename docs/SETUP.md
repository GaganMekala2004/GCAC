# GCAC user manual for VS Code

## 1. Open the dashboard and run your first scan

1. Open the GCAC source folder in VS Code 1.90 or later. In **Run and Debug**, select **Run GCAC Extension** and press **F5**. Continue in the new **Extension Development Host** window. If you already have the packaged extension, use **Extensions → … → Install from VSIX…**, select the GCAC VSIX, and open your own project folder instead.
2. Trust the workspace if you recognize its contents. Open the Command Palette and run **GCAC: Open Remediation Dashboard**.
3. Open **Local Scans → Choose Folder…** and select the root of one project. If your project lives outside the open workspace, register it first under **Settings → Browse Repository…**.
4. Select **Quick Scan** and click **Run Vulnerability Scan**. This checks secrets and configuration. It works without a model, API key, or container.
5. Look in **Recent Scan Execution History** for your target and scan ID. Open **Vulnerabilities** to inspect findings. A completed scan can have zero findings. Check each scanner’s status and coverage before drawing conclusions.

## 2. Switch between local AI, an external API, and Copilot

Select the **repository folder** in **Local Scans**, then use **AI provider → Configure provider and model**. GCAC remembers the selection for this VS Code workspace. Use the same picker to switch back.

| Choice | What to do |
| --- | --- |
| **Ollama on the Extension Host** | Install and start Ollama on the machine running the VS Code extension. In a terminal there, run `ollama list`. If empty, download a local model, for example `ollama pull mistral`. If the service is stopped, open the Ollama app or run `ollama serve`. Pick the installed model in GCAC and click **Check availability**. GCAC looks for local GGUF completion models at `127.0.0.1:11434`. [Ollama installer](https://ollama.com/download) |
| **OpenAI API** | Use your OpenAI API key and choose a chat model with JSON output. |
| **Anthropic Claude** | Use a workspace-scoped Claude API key and choose a Claude model. GCAC uses the Messages API. [Claude API](https://platform.claude.com/docs/en/api/messages/create) |
| **Google Gemini** | Use a Gemini API key and choose a chat model with JSON output. [Gemini API compatibility](https://ai.google.dev/gemini-api/docs/openai) |
| **Azure OpenAI** | Enter your Azure resource URL, resource API key, and **deployment name**. GCAC asks permission to send a small JSON test to verify the deployment. [Azure v1 endpoints](https://learn.microsoft.com/en-us/azure/foundry/openai/api-version-lifecycle) |
| **Custom OpenAI-compatible API** | Enter the provider’s public HTTPS base URL including its API prefix, for example `https://provider.example/v1/`. It must support bearer-key authentication, `GET models`, and `POST chat/completions` with JSON-object output. |
| **GitHub Copilot** | Sign in to GitHub Copilot Chat in VS Code and choose **GitHub Copilot**. From a finding, click **Run with Copilot** and follow the chat handoff. This is the default selection. |

**For any external API**, select **Allow repository**, enter the API key in the masked prompt, choose the model or deployment, and click **Check availability**. GCAC saves the key in VS Code Secret Storage. Review the destination and screened text before choosing **Send context**. To replace or remove a key, reopen the same provider and endpoint. To revoke repository access, remove its entry in VS Code User settings under `gcac.externalRepositoryAccess` or, for OpenAI, `gcac.cloudApprovedRepositories`. The extension-host setting `GCAC_DISABLE_CLOUD_AI=1` disables external API access.

**To scan with this API**, select up to 60 lines in a saved editor and use the Remediation Hub sidebar. Choose **Comprehensive Scan → AI candidate review of selected lines → Run Vulnerability Scan**. Local scanner checkboxes continue to run their own analyzers. **To remediate**, open a current, independently confirmed finding and click **Run with** followed by the provider ID. Existing runs keep their original provider when resumed.

## 3. Enable the scanners your project needs

Use **Local Scans → Comprehensive Scan**, select the applicable checkboxes, and click **Run Vulnerability Scan**.

| Project or check | Setup |
| --- | --- |
| Secrets and configuration | **Local Secrets & Configuration** is built in. Select a folder or file. |
| .NET source | Select **.NET Security Analysis**. GCAC runs the SDK’s Roslyn analyzers in a container. Follow the .NET steps below. |
| NuGet packages | Select **NuGet Dependency Audit**. From the GCAC checkout, run `node scripts/refresh-nuget-advisories.js "/absolute/path/to/workspace"` once. Supply the first open VS Code workspace folder, where GCAC writes `output/scans/`. The offline audit needs current advisories and restored project dependency graphs. |
| npm packages | Select **OSV public npm dependency intelligence** on a folder with a root `package-lock.json` version 2 or 3. Review the public package names and versions, then choose **Query OSV**. The adapter calls OSV directly. |
| CodeQL source analysis | Install the official CodeQL **bundle** with its queries. Put the executable on the extension host’s PATH or set `CODEQL_PATH` to its absolute executable path before starting VS Code. For a CLI-only installation, provision each language you use with `codeql pack download codeql/java-queries` or `codeql pack download codeql/csharp-queries`. Verify with `codeql version`, then use **Local Scans → GitHub CodeQL CLI Status → Refresh**. [CodeQL installation](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/scan-from-the-command-line/set-up-codeql-cli) |
| Optional AI triage | Select up to 60 lines in a saved source file. Keep the editor visible and use the **Remediation Hub sidebar** to enable **AI candidate review of selected lines** with Ollama or your external API. Confirm a candidate independently before remediation. |

### Prepare a .NET 9 or .NET 10 project

1. Check the project’s `global.json` SDK pin and `TargetFramework` in its project file. For a trusted project, install the matching host SDK, verify it with `dotnet --list-sdks`, and run `dotnet restore` on the target solution or project to populate its dependency graph and package cache. [Microsoft .NET SDK installers](https://dotnet.microsoft.com/en-us/download/dotnet)
2. Start Docker with Linux containers or a Linux Podman runtime. For Docker, verify `docker info` shows a running server. [Docker installation](https://docs.docker.com/get-started/get-docker/)
3. Preload the approved SDK image. From the GCAC checkout, run the commands below in a terminal with Node.js. Replace the example path with the actual project file. Copy the **entire printed reference** into the pull command. Use `podman pull` if using Podman.

   ```sh
   node -p "require('./extension/sandbox/toolchainProfiles').resolveProfileForRepository('/absolute/path/to/project.csproj', { Technology: 'dotnet' }).imageRef"
   docker pull <printed-image-reference>
   ```

4. Open **Settings → Re-check Sandbox Backend**, then rerun the .NET scanner. GCAC disables automatic image pulls during scans. The pinned image supports Linux x64, ARM64, and ARMv7. Docker selects the Linux image for the runtime.

GCAC selects the build profile from project metadata. The supplied **.NET 8, Java 17/Maven, and Node 22** profiles contain template image digests. If you see `UNPROVISIONED_TOOLCHAIN_PROFILE`, give the project’s framework and reported profile ID to the GCAC maintainer. Build-backed checks require a verified, digest-pinned image for that profile. Gradle, Ant, and Python build validation have no approved adapter in this version. Applicable source and dependency scanners can still run independently.

## 4. Remediate one finding and verify the fix

1. Open a current finding in **Vulnerabilities**. Check its repository, source path, scanner, and rule. If GCAC asks for a repository mapping, use **Settings → Browse Repository…** to select the corresponding Git repository and scan it again.
2. Click **Run with** followed by your selected provider, or **Run with Copilot**. For Copilot, submit the handoff in Chat. Follow the finding in **Active Runs**. GCAC prepares an isolated worktree and checks the baseline.
3. At **Stage 4**, inspect the proposed change and baseline evidence. Choose **Authorize Fix** when the patch matches the finding.
4. Review the actual diff, test count and results, originating scanner re-scan, and security review. If a check is blocked, partial, or ran zero tests, open the recorded reason and correct that prerequisite before retrying.
5. At **Stage 8**, choose **Final Sign-off** after verification passes. Review the saved artifacts in `remediation-output/<finding-id>/`. Publishing the reviewed change is a separate human action.

**If results look stale**, select **Force Fresh Scan** and rerun on the same target. **If only some checks ran**, inspect the per-scanner reason in the scan results. Quick Scan covers secrets and configuration only.

**After updating from 2.0.0**, open the owning Git repository, select **Force Fresh Scan**, and start a new run from its results. Isolated worktrees use committed source. Commit reviewed framework or source changes in the target repository before rescanning. GCAC regression fixtures remain visible for manual review. A `SCAN-SECRET` ID identifies the scanner; its rule and CWE identify the finding type.


### When Stage 4 approval stops

Open the finding in the Remediation Hub, refresh it, and review **Patch Diff**. Confirm the file and SHA-256 before selecting **Authorize Fix**. Every new run needs its own review, even for the same finding.

If you rejected the proposal or its approval expired, start a new remediation and review the new patch. If GCAC reports that the current approval was consumed during an interrupted patch application, inspect the isolated worktree and run evidence before starting a new run. Keep the original evidence for review.


For a NuGet finding, run a fresh scan after restoring the project. GCAC can propose a version for a directly declared dependency when a newer stable package is present in the local NuGet.org cache and falls outside every affected range in the current advisory snapshot. Transitive dependencies and packages without a verified target require dependency review.
