# Migration and readiness

Install the local VSIX with Extensions → Install from VSIX in a trusted VS Code workspace. Existing Copilot commands and the Run with Copilot button remain available. Existing run records without provider metadata resume with Copilot. New direct runs preserve their provider and model across approval and retry.

Open the dashboard’s scanner view and choose **Configure provider and model**. For Ollama, start a trusted runtime on the Extension Host and select an installed coding model. For OpenAI, classify the repository, add its exact canonical path to the user-level gcac.cloudApprovedRepositories setting, select OpenAI, enter the key in native input, and select a Chat Completions model supporting JSON output. Use **Check availability**. The host requests separate consent before disclosing source. Selecting a model never triggers a remediation.

Select a mapped finding and use **Run with ollama** or **Run with openai**. Review the diff, test result, targeted scan and security review. Local credentials can require operator rotation and revocation even after the source repair passes. Optional scanning can combine the existing local adapters, public npm lockfile intelligence and selected-line AI candidate review.

Build tooling used Node 22.23.5 and @vscode/vsce 3.6.2 on PATH. Run `npm run package:vsix -- --out out/gcac-2.0.0.vsix` after creating out. The runtime remains dependency-free. Tests use initialized local sample repositories. A plain clone of this repository can have empty Git links with no .gitmodules metadata.

**Pilot decision** remains pending authenticated Copilot and approved live OpenAI acceptance. Independent security and platform review are outstanding. The repository has no distribution license file. Publishing and redistribution require owner review.
