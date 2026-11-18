const { test } = require('node:test');
const assert = require('node:assert/strict');
const { Ollama, validate } = require('../../extension/providers/direct');
test('Ollama checks installed model and rejects remote-backed inference before chat', async () => {
    const model = 'local:latest';
    const adapter = new Ollama(async (url) => {
        assert.equal(url.origin, 'http://127.0.0.1:11434');
        if (url.pathname === '/api/tags') return { models: [{ name: model, details: { format: 'gguf' } }] };
        assert.equal(url.pathname, '/api/show');
        return { remote_host: 'cloud' };
    });
    await assert.rejects(adapter.check('absent'), /unavailable/);
    await assert.rejects(adapter.infer(model, 'prompt'), /local completion/);
});
test('v1 edit contract accepts exact replacements and rejects authority or tool fields', () => {
    const edits = [{ oldText: 'a', newText: 'b' }];
    assert.deepEqual(validate('proposal', JSON.stringify({ edits })), { edits });
    for (const bad of ['bad', '{"edits":[]}', JSON.stringify({ edits, approved: true })])
        assert.throws(() => validate('proposal', bad));
});
const { OpenAIChat } = require('../../extension/providers/openai');
test('OpenAI checks repository policy, consent, SecretStorage and fixed destination', async () => {
    let allowed = false,
        consent = false,
        calls = 0;
    const adapter = new OpenAIChat({
        allowed: () => allowed,
        consent: () => consent,
        secrets: {
            get(key) {
                assert.equal(key, 'gcac.openai.key');
                return 'fixture';
            }
        },
        send(url, options) {
            calls++;
            assert.equal(url.href, 'https://api.openai.com/v1/chat/completions');
            assert.equal(options.key, 'fixture');
            if (calls === 1) throw Object.assign(Error('Unavailable'), { status: 503 });
            return { choices: [{ finish_reason: 'stop', message: { content: '{}' } }] };
        }
    });
    await assert.rejects(adapter.infer('example', 'JSON', {}));
    allowed = true;
    await assert.rejects(adapter.infer('example', 'JSON', {}));
    assert.equal(calls, 0);
    consent = true;
    assert.equal(await adapter.infer('example', 'JSON', {}), '{}');
    assert.equal(calls, 2);
});
const { requestJson } = require('../../extension/providers/transport');
const { ProviderHost } = require('../../extension/providers/host');
test('network boundary rejects remote Ollama, custom TLS hosts and local credential forwarding', async () => {
    for (const url of [
        'http://example.org:11434',
        'https://127.0.0.1',
        'https://api.openai.com.example.org',
        'http://169.254.169.254'
    ]) {
        await assert.rejects(requestJson(new URL(url)), /denied/);
    }
    await assert.rejects(requestJson(new URL('http://127.0.0.1:11434'), { key: 'fictional' }), /denied/);
});
test('OpenAI never widens repository permission from workspace settings or a partial match', () => {
    let settings = { workspaceValue: ['/repo'] };
    const host = new ProviderHost(
        { workspace: { isTrusted: true, getConfiguration: () => ({ inspect: () => settings }) } },
        {}
    );
    assert.equal(host.cloudAllowed('/repo'), false);
    settings = { globalValue: ['/repo'] };
    assert.equal(host.cloudAllowed('/repo'), true);
    assert.equal(host.cloudAllowed('/rep'), false);
    settings = { globalValue: '/repo' };
    assert.equal(host.cloudAllowed('/rep'), false);
});
test('auth, quota and malformed external responses do not retry through another provider', async () => {
    for (const status of [401, 403, 429]) {
        let count = 0;
        const adapter = new OpenAIChat({
            allowed: () => true,
            consent: () => true,
            secrets: { get: () => 'fixture' },
            send() {
                count++;
                throw Object.assign(Error('Provider HTTP ' + status), { status });
            }
        });
        await assert.rejects(adapter.infer('fixture', 'JSON', {}), new RegExp(String(status)));
        assert.equal(count, 1);
    }
    const adapter = new OpenAIChat({
        allowed: () => true,
        consent: () => true,
        secrets: { get: () => 'fixture' },
        send: () => ({ choices: [] })
    });
    await assert.rejects(adapter.infer('fixture', 'JSON', {}), /Incomplete/);
});
test('request deadline and cancellation dispose the transport before accepting any response', async (t) => {
    const { EventEmitter } = require('node:events');
    const { createRunCancellation } = require('../../extension/runCancellation');
    t.mock.method(require('node:http'), 'request', (_, options) => {
        const req = new EventEmitter();
        req.end = () => {};
        options.signal.addEventListener('abort', () => req.emit('error', Error('aborted')));
        return req;
    });
    const url = new URL('http://127.0.0.1:11434/api/tags');
    await assert.rejects(requestJson(url, { timeout: 10 }), /timed out/);
    const token = createRunCancellation();
    const pending = requestJson(url, { cancellationToken: token });
    token.cancel();
    await assert.rejects(pending, /cancelled/);
});
test('provider configuration obtains the API key through a masked native prompt and only persists it to SecretStorage', async () => {
    const saved = new Map();
    const selected = [];
    const answers = [{ id: 'openai' }, 'fixture-model'];
    const host = new ProviderHost(
        {
            window: {
                showQuickPick: () => answers.shift(),
                showInputBox: (opts) => {
                    assert.equal(opts.password, true);
                    return 'unit-test-secret';
                }
            }
        },
        {
            secrets: { get: (k) => saved.get(k), store: (k, v) => saved.set(k, v) },
            workspaceState: { update: (k, v) => selected.push(v) }
        }
    );
    host.adapter = () => ({ models: () => ['fixture-model'], check: () => {} });
    await host.configure('/repo');
    assert.deepEqual(selected, [{ id: 'openai', model: 'fixture-model' }]);
    assert.equal(saved.get('gcac.openai.key'), 'unit-test-secret');
});
