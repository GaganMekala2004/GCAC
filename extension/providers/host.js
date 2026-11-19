'use strict';
const { DirectClient, Ollama } = require('./direct');
const { providers, endpointFor, keyName } = require('./endpoints');
const { OpenAIChat } = require('./openai');
const { DEFAULT_PROVIDER } = require('./copilot');

class ProviderHost {
    constructor(vscode, context) {
        this.vscode = vscode;
        this.context = context;
    }
    selection() {
        return this.context.workspaceState?.get('gcac.provider') || { id: DEFAULT_PROVIDER };
    }
    cloudAllowed(repository, id = 'openai', base) {
        if (process.env.GCAC_DISABLE_CLOUD_AI === '1') return false;
        const { workspace } = this.vscode;
        if (!workspace.isTrusted || !repository) return false;
        if (id !== 'openai') {
            const grants = workspace.getConfiguration('gcac').inspect('externalRepositoryAccess')?.globalValue;
            return Array.isArray(grants) && grants.some(g => g?.repository === repository && g.endpoint === base && g.provider === id);
        }
        const approved = workspace.getConfiguration('gcac').inspect('cloudApprovedRepositories')?.globalValue;
        return (
            workspace.isTrusted &&
            typeof repository === 'string' &&
            Array.isArray(approved) &&
            approved.includes(repository)
        );
    }
    async status(repository) {
        const { id, model, endpoint } = this.selection();
        if (id === DEFAULT_PROVIDER)
            return { id, message: 'Interactive Chat handoff. Results require verified engine evidence.' };
        try {
            const adapter = this.adapter(id, repository, endpoint);
            await adapter.check(model, { timeout: id === 'azure' ? 90000 : 10000, probeDeployment: true });
            const destination = id === 'ollama' ? 'Extension Host loopback' : adapter.base;
            const message = id === 'azure' ? 'Deployment returned valid JSON.' :
                'Model available. Structured output is validated per request.';
            return { id, model, endpoint, message: destination + ' · ' + message };
        } catch (error) {
            return { id, model, endpoint, message: error.message };
        }
    }
    adapter(id, repository, endpoint) {
        if (id === 'ollama') return new Ollama();
        const base = endpointFor(id, endpoint);
        const { window } = this.vscode;
        return new OpenAIChat({
            id, endpoint: base,
            secrets: this.context.secrets,
            allowed: () => this.cloudAllowed(repository, id, base),
            consent: async (model, prompt) =>
                (await window.showWarningMessage(
                    'Send this screened context to ' + base + ' using ' + model + '?',
                    { modal: true, detail: repository + '\n\n' + prompt },
                    'Send context'
                )) === 'Send context'
        });
    }
    async approveEndpoint(repository, id, endpoint) {
        if (this.cloudAllowed(repository, id, endpoint)) return true;
        const { workspace, window, ConfigurationTarget } = this.vscode;
        if (!repository || !workspace.isTrusted || process.env.GCAC_DISABLE_CLOUD_AI === '1')
            throw Error('External AI requires a selected trusted repository and enabled cloud access');
        const config = workspace.getConfiguration('gcac');
        if (await window.showWarningMessage('Allow ' + providers[id].label + ' for this repository?',
            { modal: true, detail: repository + '\n' + endpoint }, 'Allow repository') !== 'Allow repository') return false;
        const setting = id === 'openai' ? 'cloudApprovedRepositories' : 'externalRepositoryAccess';
        const grants = config.inspect(setting)?.globalValue || [];
        const grant = id === 'openai' ? repository : { repository, provider: id, endpoint };
        await config.update(setting, [...grants, grant], ConfigurationTarget.Global);
        return true;
    }
    client(selection, repository) {
        if (typeof selection.model !== 'string' || !selection.model || selection.model.length > 200)
            throw Error('Invalid selected model');
        return new DirectClient(this.adapter(selection.id, repository, selection.endpoint), selection.model);
    }
    async configure(repository) {
        const { window } = this.vscode;
        const choice = await window.showQuickPick(
            [
                { label: 'GitHub Copilot', id: DEFAULT_PROVIDER },
                { label: 'Ollama on the Extension Host', id: 'ollama' },
                ...Object.entries(providers).map(([id, entry]) => ({ id, label: entry.label }))
            ],
            { title: 'AI provider' }
        );
        if (!choice) return;
        let model;
        let endpoint;
        if (choice.id !== DEFAULT_PROVIDER) {
            let enterKey = false;
            let credential;
            if (Object.hasOwn(providers, choice.id)) {
                let input;
                if (!providers[choice.id].base) {
                    input = await window.showInputBox({ prompt: 'Public HTTPS API base URL for ' + choice.label,
                        placeHolder: choice.id === 'azure' ? 'https://my-resource.openai.azure.com/openai/v1/' : 'https://provider.example/v1/',
                        ignoreFocusOut: true });
                    if (!input) return;
                }
                const base = endpointFor(choice.id, input);
                if (input) endpoint = base;
                credential = keyName(choice.id, base);
                enterKey = !(await this.context.secrets.get(credential));
                if (!enterKey) {
                    const action = await window.showQuickPick(['Use stored key', 'Replace key', 'Remove key'], { title: 'Credential for ' + base });
                    if (!action) return;
                    if (action === 'Remove key') {
                        await this.context.secrets.delete(credential);
                        return;
                    }
                    enterKey = action === 'Replace key';
                }
                if (!await this.approveEndpoint(repository, choice.id, base)) return;
            }
            if (enterKey) {
                const key = await window.showInputBox({
                    prompt: 'API key for ' + endpointFor(choice.id, endpoint),
                    password: true,
                    ignoreFocusOut: true
                });
                if (!key) return;
                await this.context.secrets.store(credential, key);
            }
            const adapter = this.adapter(choice.id, repository, endpoint);
            if (choice.id === 'azure') {
                model = (await window.showInputBox({ prompt: 'Azure chat model deployment name', ignoreFocusOut: true }))?.trim();
            } else {
                const models = await adapter.models();
                if (!models.length) throw Error('No installed or accessible models');
                model = await window.showQuickPick(models, { title: 'Select a model with JSON output support' });
            }
            if (!model) return;
            await adapter.check(model, { probeDeployment: true });
        }
        await this.context.workspaceState.update('gcac.provider', { id: choice.id, model, ...(endpoint ? { endpoint } : {}) });
    }
}
module.exports = { ProviderHost };
