'use strict';
const { requestJson } = require('./transport');

class OpenAIChat {
    constructor({ secrets, allowed, consent, send = requestJson }) {
        Object.assign(this, { secrets, allowed, consent, send, id: 'openai' });
    }
    async call(path, options) {
        const url = new URL(path, 'https://api.openai.com');
        for (let attempt = 0; ; attempt++) {
            if (!this.allowed()) throw Error('Repository policy prohibits external AI');
            const key = await this.secrets.get('gcac.openai.key');
            if (!key) throw Error('OpenAI API key is unconfigured');
            try {
                return await this.send(url, { ...options, key });
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
        const { data } = await this.call('/v1/models', options);
        return data.map((item) => item.id).filter((id) => typeof id === 'string');
    }
    async check(model, options) {
        if (!(await this.models(options)).includes(model)) throw Error('Selected external model unavailable');
    }
    async infer(model, prompt, options) {
        if (!this.allowed() || !(await this.consent(model, prompt)))
            throw Error('External AI transmission denied');
        if (options.cancellationToken?.isCancellationRequested) throw Error('Provider request cancelled');
        const result = await this.call('/v1/chat/completions', {
            ...options,
            body: {
                model,
                store: false,
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
