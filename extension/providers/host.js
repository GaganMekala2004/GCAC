'use strict';
const { DirectClient, Ollama } = require('./direct');
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
    cloudAllowed(repository) {
        if (process.env.GCAC_DISABLE_CLOUD_AI === '1') return false;
        const { workspace } = this.vscode;
        const approved = workspace.getConfiguration('gcac').inspect('cloudApprovedRepositories')?.globalValue;
        return (
            workspace.isTrusted &&
            typeof repository === 'string' &&
            Array.isArray(approved) &&
            approved.includes(repository)
        );
    }
    async status(repository) {
        const { id, model } = this.selection();
        if (id === DEFAULT_PROVIDER)
            return { id, message: 'Interactive Chat handoff. Results require verified engine evidence.' };
        const keyConfigured = id === 'openai' && Boolean(await this.context.secrets.get('gcac.openai.key'));
        const privacy =
            id === 'ollama'
                ? 'Extension Host: ' + require('node:os').hostname() + ' · loopback only'
                : 'api.openai.com · key ' +
                  (keyConfigured ? 'configured' : 'missing') +
                  ' · repository ' +
                  (this.cloudAllowed(repository) ? 'approved' : 'denied') +
                  ' · consent required';
        try {
            await this.adapter(id, repository).check(model, { timeout: 5000 });
            return {
                id,
                model,
                message: privacy + ' · model available. Structured output is validated per request.'
            };
        } catch (error) {
            return { id, model, message: privacy + ' · ' + error.message };
        }
    }
    adapter(id, repository) {
        if (id === 'ollama') return new Ollama();
        if (id !== 'openai') throw Error('Unknown inference provider');
        const { window } = this.vscode;
        return new OpenAIChat({
            secrets: this.context.secrets,
            allowed: () => this.cloudAllowed(repository),
            consent: async (model, prompt) =>
                (await window.showWarningMessage(
                    'Send this screened context to api.openai.com using ' + model + '?',
                    { modal: true, detail: repository + '\n\n' + prompt },
                    'Send context'
                )) === 'Send context'
        });
    }
    client(selection, repository) {
        if (typeof selection.model !== 'string' || !selection.model || selection.model.length > 200)
            throw Error('Invalid selected model');
        return new DirectClient(this.adapter(selection.id, repository), selection.model);
    }
    async configure(repository) {
        const { window } = this.vscode;
        const choice = await window.showQuickPick(
            [
                { label: 'GitHub Copilot', id: DEFAULT_PROVIDER },
                { label: 'Ollama on the Extension Host', id: 'ollama' },
                { label: 'OpenAI API (api.openai.com)', id: 'openai' }
            ],
            { title: 'AI provider' }
        );
        if (!choice) return;
        let model;
        if (choice.id !== DEFAULT_PROVIDER) {
            let enterKey = false;
            if (choice.id === 'openai') {
                enterKey = !(await this.context.secrets.get('gcac.openai.key'));
                if (!enterKey) {
                    const action = await window.showQuickPick(['Use stored key', 'Replace key', 'Remove key'], { title: 'OpenAI credential for api.openai.com' });
                    if (!action) return;
                    if (action === 'Remove key') {
                        await this.context.secrets.delete('gcac.openai.key');
                        return;
                    }
                    enterKey = action === 'Replace key';
                }
            }
            if (enterKey) {
                const key = await window.showInputBox({
                    prompt: 'OpenAI API key for api.openai.com',
                    password: true,
                    ignoreFocusOut: true
                });
                if (!key) return;
                await this.context.secrets.store('gcac.openai.key', key);
            }
            const adapter = this.adapter(choice.id, repository);
            const models = await adapter.models();
            if (!models.length) throw Error('No installed or accessible models');
            model = await window.showQuickPick(models, { title: 'Select a model with JSON output support' });
            if (!model) return;
            await adapter.check(model);
        }
        await this.context.workspaceState.update('gcac.provider', { id: choice.id, model });
    }
}
module.exports = { ProviderHost };
