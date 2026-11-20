'use strict';
const { requestJson } = require('./transport');
const { outboundContextGate } = require('../outboundContextGate');
const { redactCredentials } = require('../credentialRedaction');

const responseFields = {
    candidate: ['found', 'line', 'cwe', 'reasoning', 'limitations'],
    classification: [
        'cwe',
        'severity',
        'exploitability',
        'route',
        'strategy',
        'attackVector',
        'confidence',
        'summary'
    ],
    analysis: ['dataFlow', 'rootCause', 'securityImpact', 'proposedFix', 'affectedLines', 'summary'],
    proposal: ['edits'],
    review: ['rating', 'summary', 'auditChecks']
};
function schema(operation) {
    const properties = {};
    for (const key of responseFields[operation]) {
        if (key === 'found') properties[key] = { type: 'boolean' };
        else if (key === 'line') properties[key] = { type: 'integer', minimum: 0 };
        else if (key === 'confidence') properties[key] = { type: 'number', minimum: 0, maximum: 100 };
        else if (key === 'auditChecks')
            properties[key] = { type: 'array', items: { type: 'string' }, minItems: 1 };
        else if (key === 'edits')
            properties[key] = {
                type: 'array',
                minItems: 1,
                items: {
                    type: 'object',
                    properties: { oldText: { type: 'string' }, newText: { type: 'string' } },
                    required: ['oldText', 'newText'],
                    additionalProperties: false
                }
            };
        else if (key === 'rating') properties[key] = { enum: ['PASS', 'FAIL', 'BLOCKED', 'NOT_VERIFIED'] };
        else properties[key] = { type: 'string', minLength: 1 };
    }
    return { type: 'object', properties, required: responseFields[operation], additionalProperties: false };
}
function validate(operation, content) {
    let result;
    try {
        result = JSON.parse(content);
    } catch {
        throw Error('Invalid model response JSON');
    }
    const fields = responseFields[operation];
    const validText = (x) => typeof x === 'string' && x.trim().length > 0;
    if (
        !fields ||
        !result ||
        Object.keys(result).length !== fields.length ||
        !fields.every((key) => Object.hasOwn(result, key))
    )
        throw Error('Unexpected model response fields');
    for (const key of fields) {
        const value = result[key];
        let valid = validText(value);
        if (key === 'found') valid = typeof value === 'boolean';
        if (key === 'line') valid = Number.isInteger(value) && value >= 0;
        if (key === 'confidence') valid = Number.isFinite(value) && value >= 0 && value <= 100;
        if (key === 'rating') valid = ['PASS', 'FAIL', 'BLOCKED', 'NOT_VERIFIED'].includes(value);
        if (key === 'auditChecks') valid = Array.isArray(value) && value.length > 0 && value.every(validText);
        if (key === 'edits')
            valid =
                Array.isArray(value) &&
                value.length > 0 &&
                value.length <= 64 &&
                value.every(
                    (edit) =>
                        edit &&
                        Object.keys(edit).length === 2 &&
                        validText(edit.oldText) &&
                        typeof edit.newText === 'string'
                );
        if (!valid) throw Error('Invalid model field ' + key);
    }
    return result;
}

class Ollama {
    constructor(send = requestJson) {
        this.send = send;
        this.id = 'ollama';
    }
    call(route, options) {
        return this.send(new URL(route, 'http://127.0.0.1:11434'), options);
    }
    async models(options) {
        const { models } = await this.call('/api/tags', options);
        return models
            .filter(
                (m) =>
                    m.details?.format === 'gguf' &&
                    typeof m.name === 'string' &&
                    !m.remote_model &&
                    !m.remote_host
            )
            .map((m) => m.name);
    }
    async check(model, options) {
        if (!(await this.models(options)).includes(model))
            throw Error('Selected local GGUF model is unavailable');
        const info = await this.call('/api/show', { ...options, body: { model } });
        if (
            info.remote_model ||
            info.remote_host ||
            info.details?.format !== 'gguf' ||
            !info.capabilities?.includes('completion')
        )
            throw Error('Model does not declare local completion support');
    }
    async infer(model, prompt, options) {
        await this.check(model, options);
        const result = await this.call('/api/chat', {
            ...options,
            // Local model loading and generation share this request deadline.
            timeout: options.timeout ?? 300000,
            body: {
                model,
                stream: false,
                format: options.schema,
                options: { temperature: 0 },
                messages: [{ role: 'user', content: prompt }]
            }
        });
        if (
            result.done !== true ||
            result.done_reason === 'length' ||
            result.model !== model ||
            result.message?.tool_calls?.length
        )
            throw Error('Incomplete or unexpected local inference');
        this.lastUsage = {};
        if (Number.isSafeInteger(result.prompt_eval_count))
            this.lastUsage.prompt_tokens = result.prompt_eval_count;
        if (Number.isSafeInteger(result.eval_count)) this.lastUsage.completion_tokens = result.eval_count;
        return result.message?.content;
    }
}

// Version 1 response contract. Engine owns identity, target selection, git diff and decisions.
class DirectClient {
    constructor(adapter, model) {
        this.adapter = adapter;
        this.model = model;
        this.strict = true;
        this.requests = [];
    }
    getCapabilities() {
        return {
            interactiveHandoff: false,
            directInference: true,
            structuredOutput: true,
            cancellation: true,
            providerManagedTools: false,
            contractVersion: 1
        };
    }
    async getAvailableModels(options) {
        await this.adapter.check(this.model, options);
        return [{ id: this.model, name: this.model, vendor: this.adapter.id }];
    }
    async generateJson(rawPrompt, context) {
        const prompt = redactCredentials(rawPrompt);
        const sourceCode = redactCredentials(context.sourceCode);
        outboundContextGate.assertAllowed({ ...context, prompt, sourceCode });
        const content = await this.adapter.infer(this.model, prompt, {
            cancellationToken: context.cancellationToken,
            schema: schema(context.operation)
        });
        const value = validate(context.operation, content);
        this.requests.push({
            operation: context.operation,
            model: this.model,
            provider: this.adapter.id,
            bytes: Buffer.byteLength(prompt),
            usage: this.adapter.lastUsage,
            contractVersion: 1
        });
        return value;
    }
    async generateCompletion(prompt, context) {
        return JSON.stringify(await this.generateJson(prompt, context));
    }
}
module.exports = { DirectClient, Ollama, validate };
