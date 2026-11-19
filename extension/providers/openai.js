'use strict';
const { requestJson } = require('./transport');

const { providers, endpointFor, keyName } = require('./endpoints');

class OpenAIChat {
    constructor({ secrets, allowed, consent, send = requestJson, id = 'openai', endpoint }) {
        Object.assign(this, { secrets, allowed, consent, send, id });
        this.base = endpointFor(id, endpoint);
    }
    async call(path, options) {
        const url = new URL(path, this.base);
        for (let attempt = 0; ; attempt++) {
            if (!this.allowed()) throw Error('Repository policy prohibits external AI');
            const key = await this.secrets.get(keyName(this.id, this.base));
            if (!key) throw Error(providers[this.id].label + ' API key is unconfigured');
            try {
                return await this.send(url, { ...options, key, provider: this.id, endpoint: this.base });
            } catch (error) {
                if (
                    attempt ||
                    (![502, 503, 504].includes(error.status) && !error.retryable) ||
                    options.cancellationToken?.isCancellationRequested
                )
                    throw error;
            }
        }
    }
    async models(options = {}) {
        const { data } = await this.call('models', options);
        return data.map((item) => item.id).filter((id) => typeof id === 'string');
    }
    async check(model, options) {
        if (this.id === 'azure') {
            // Azure inference uses deployment names. Listing catalog models does
            // not establish that a deployment exists or accepts this key.
            if (!this.allowed()) throw Error('Repository policy prohibits external AI');
            if (!await this.secrets.get(keyName(this.id, this.base))) throw Error('Azure API key is unconfigured');
            if (options?.probeDeployment) {
                const reply = await this.infer(model, 'Return a JSON object containing only {"ready":true}.', options);
                if (JSON.parse(reply)?.ready !== true) throw Error('Deployment did not return the expected JSON');
            }
            return;
        }
        const models = await this.models(options);
        if (!models.includes(model)) throw Error('Selected external model unavailable');
    }
    async infer(model, prompt, options) {
        if (!this.allowed() || !(await this.consent(model, prompt)))
            throw Error('External AI transmission denied');
        if (options.cancellationToken?.isCancellationRequested) throw Error('Provider request cancelled');
        if (this.id === 'anthropic') {
            const result = await this.call('messages', {
                ...options,
                body: { model, max_tokens: 4096, system: 'Return only the requested JSON object.',
                    messages: [{ role: 'user', content: prompt }] }
            });
            if (result.stop_reason !== 'end_turn' || result.content?.length !== 1 || result.content[0].type !== 'text')
                throw Error('Incomplete or refused Claude response');
            this.lastUsage = { prompt_tokens: result.usage?.input_tokens, completion_tokens: result.usage?.output_tokens };
            return result.content[0].text;
        }
        const result = await this.call('chat/completions', {
            ...options,
            body: {
                model,
                ...(this.id === 'openai' ? { store: false } : {}),
                response_format: { type: 'json_object' },
                messages: [{ role: 'user', content: prompt }]
            }
        });
        const choice = result.choices?.[0];
        if (choice?.finish_reason !== 'stop' || choice.message?.refusal || choice.message?.tool_calls)
            throw Error('Incomplete or refused external inference');
        this.lastUsage = Object.fromEntries(
            ['prompt_tokens', 'completion_tokens', 'total_tokens']
                .filter((key) => Number.isSafeInteger(result.usage?.[key]))
                .map((key) => [key, result.usage[key]])
        );
        return choice.message?.content;
    }
}
module.exports = { OpenAIChat };
