/**
 * GitHub Copilot LLM Client for GCAC Vulnerability Remediation
 * 
 * Powered EXCLUSIVELY by GitHub Copilot via VS Code Language Model API (vscode.lm).
 * No local LLMs, no external third-party endpoints, no templates, no mock data.
 */

let vscode = null;
try {
    vscode = require('vscode');
} catch (e) {
    vscode = null;
}

class LlmClient {
    constructor() {
        this.lastUsedModel = null;
    }

    /**
     * Determines whether GitHub Copilot is available in the current VS Code environment
     */
    async isAvailable() {
        try {
            const models = await this.getAvailableModels();
            return models.length > 0;
        } catch (e) {
            return false;
        }
    }

    /**
     * Returns list of available GitHub Copilot models from vscode.lm
     */
    async getAvailableModels() {
        const available = [];

        if (vscode && vscode.lm && typeof vscode.lm.selectChatModels === 'function') {
            try {
                // Try selecting GitHub Copilot vendor models first
                let copilotModels = await vscode.lm.selectChatModels({ vendor: 'copilot' });
                
                // Fallback: If empty, query all chat models and filter
                if (!copilotModels || copilotModels.length === 0) {
                    copilotModels = await vscode.lm.selectChatModels();
                }

                if (copilotModels && copilotModels.length > 0) {
                    for (const m of copilotModels) {
                        available.push({
                            vendor: m.vendor || 'copilot',
                            family: m.family || 'copilot',
                            name: m.name || m.id,
                            id: m.id,
                            instance: m
                        });
                    }
                }
            } catch (err) {
                console.warn('[LlmClient] Error inspecting vscode.lm models:', err.message);
            }
        }

        return available;
    }

    /**
     * Executes a prompt with GitHub Copilot and returns the full text response
     * Prioritizes GPT-4o and GPT-4o-mini (available in GitHub Student Developer Pack)
     * with automatic fallback if an unentitled model is encountered.
     * @param {string} prompt Text prompt to execute
     * @param {object} options { onChunk: (text) => void, cancellationToken, systemPrompt?: string }
     * @returns {Promise<string>} Full response text
     */
    async generateCompletion(prompt, options = {}) {
        const models = await this.getAvailableModels();

        if (models.length === 0) {
            throw new Error(
                'GitHub Copilot is required: No active GitHub Copilot language model was found.\n' +
                'Please ensure GitHub Copilot is installed, enabled, and signed in to VS Code.\n' +
                'Local LLMs and mock templates are completely disabled.'
            );
        }

        // Sort models by preference for GitHub Copilot Student Developer Pack:
        // 1. gpt-4o (highest quality, included in Student plan)
        // 2. gpt-4o-mini (fast & low quota, included in Student plan)
        // 3. gpt-4 / copilot default
        // 4. other models
        const sortedModels = [...models].sort((a, b) => {
            const score = (m) => {
                const id = ((m.family || '') + ' ' + (m.id || '') + ' ' + (m.name || '')).toLowerCase();
                if (id.includes('gpt-4o') && !id.includes('mini')) return 4;
                if (id.includes('gpt-4o-mini')) return 3;
                if (id.includes('gpt-4')) return 2;
                if (id.includes('copilot')) return 1;
                return 0;
            };
            return score(b) - score(a);
        });

        const messages = [];

        if (options.systemPrompt) {
            try {
                if (vscode.LanguageModelChatMessage && vscode.LanguageModelChatMessage.Assistant) {
                    messages.push(vscode.LanguageModelChatMessage.User(`[SYSTEM INSTRUCTION]\n${options.systemPrompt}`));
                    messages.push(vscode.LanguageModelChatMessage.Assistant('Understood. I will follow all instructions strictly.'));
                }
            } catch (e) {}
        }

        messages.push(vscode.LanguageModelChatMessage.User(prompt));

        const cancellationToken = options.cancellationToken || (vscode.CancellationTokenSource ? new vscode.CancellationTokenSource().token : undefined);

        let lastError = null;
        for (const selectedModel of sortedModels) {
            try {
                this.lastUsedModel = selectedModel.name || selectedModel.id;
                const chatResponse = await selectedModel.instance.sendRequest(messages, {}, cancellationToken);

                let fullText = '';
                for await (const chunk of chatResponse.text) {
                    fullText += chunk;
                    if (options.onChunk) {
                        options.onChunk(chunk);
                    }
                }

                return fullText;
            } catch (err) {
                lastError = err;
                console.warn(`[LlmClient] Model '${selectedModel.name || selectedModel.id}' failed: ${err.message}. Trying next available model...`);
            }
        }

        throw new Error(`All available GitHub Copilot models failed. Last error: ${lastError ? lastError.message : 'Unknown error'}`);
    }

    /**
     * Calls GitHub Copilot and safely parses JSON from the response
     */
    async generateJson(prompt, options = {}) {
        const augmentedPrompt = `${prompt}\n\nIMPORTANT: Output valid JSON only. Do not wrap with explanation text outside the JSON.`;
        const rawText = await this.generateCompletion(augmentedPrompt, options);

        // Try direct parse
        try {
            return JSON.parse(rawText.trim());
        } catch (e) {}

        // Try extracting JSON from markdown code fence ```json ... ```
        const jsonBlockMatch = rawText.match(/```(?:json)?\s*([\s\S]*?)```/i);
        if (jsonBlockMatch) {
            try {
                return JSON.parse(jsonBlockMatch[1].trim());
            } catch (e) {}
        }

        // Try extracting first balanced { ... }
        const braceMatch = rawText.match(/(\{[\s\S]*\})/);
        if (braceMatch) {
            try {
                return JSON.parse(braceMatch[1].trim());
            } catch (e) {}
        }

        throw new Error(`Failed to parse GitHub Copilot response as JSON. Raw response:\n${rawText.slice(0, 500)}`);
    }
}

const defaultClient = new LlmClient();

module.exports = {
    LlmClient,
    llmClient: defaultClient
};
