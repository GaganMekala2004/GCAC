# Provider contracts

| Provider | Entry and model selection | Observability |
| --- | --- | --- |
| Copilot | Native Chat handoff via workbench.action.chat.open. Existing participant uses the VS Code LM API. | Handoff has no native tool telemetry. Engine-controlled calls produce stage evidence. |
| Ollama | Extension Host loopback at 127.0.0.1:11434. GET /api/tags and POST /api/show verify a local GGUF model with completion capability. POST /api/chat uses stream false and an operation-specific JSON schema. | Per-request cancellation and deadline. Remote-backed models are rejected. No model-start or download flow is shipped. |
| OpenAI | HTTPS api.openai.com. GET /v1/models and POST /v1/chat/completions. Native selection requires a repository permitted for cloud inference. | JSON-object output with client-side validation. Refusals, tool calls and incomplete completions fail. Numeric usage fields are retained when returned. |

DirectClient implements the engine’s getAvailableModels, generateJson and generateCompletion interface. Operation names select version 1 classification, analysis, proposal, review or candidate schemas. The direct provider interface uses models, check and infer. Cancellation uses the run’s token subscription. A provider returns data only. The engine constructs finding and repository identity, target paths, exact diff, SHA-256 and approval evidence.

The proposal contract requires an array of exact oldText/newText replacements. Extra fields or empty edits fail validation. The engine checks scope, applies replacements to a candidate, compiles when applicable, and generates the diff. Models supply advisory classification and review. Scanner severity and terminal outcomes are controlled separately.

OSV submits approved public npm package names, ecosystem and exact versions from the root lockfile. Versions outside supported lockfile metadata are omitted with a coverage warning. Additional OSV pages produce partial coverage. Original OSV severity data is retained and an unmapped severity is displayed as Unknown. AI review covers at most 60 approved lines. A candidate records provider, model, source digest, location, reasoning and limitations. An independent scanner finding can proceed to remediation. An AI candidate alone cannot.

API references are the [Ollama chat API](https://docs.ollama.com/api/chat), [Ollama model list](https://docs.ollama.com/api/tags), [OpenAI Chat Completions](https://platform.openai.com/docs/api-reference/chat/create) and [OSV query](https://google.github.io/osv.dev/api/post-v1-query/).
