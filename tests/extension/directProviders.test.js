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
    await assert.rejects(requestJson(url, { timeout: 10 }), /timed out after 10 ms/);
    const token = createRunCancellation();
    const pending = requestJson(url, { cancellationToken: token });
    token.cancel();
    await assert.rejects(pending, /^Error: Provider request cancelled$/);
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
    host.cloudAllowed = () => true;
    host.adapter = () => ({ models: () => ['fixture-model'], check: () => {} });
    await host.configure('/repo');
    assert.deepEqual(selected, [{ id: 'openai', model: 'fixture-model' }]);
    assert.equal(saved.get('gcac.openai.key'), 'unit-test-secret');
});

const { endpointFor, keyName } = require('../../extension/providers/endpoints');
const { DirectClient } = require('../../extension/providers/direct');
for (const [id, input] of [
    ['anthropic'], ['gemini'], ['azure', 'https://demo.openai.azure.com'],
    ['compatible', 'https://gateway.example/v1']
]) {
    test(id + ' uses the selected endpoint and credential for candidate scanning and repair proposals', async () => {
        const base = endpointFor(id, input);
        const selections = [];
        const candidate = { found: false, line: 0, cwe: 'none', reasoning: 'No evidence', limitations: 'Selected lines only' };
        const proposal = { edits: [{ oldText: 'old', newText: 'new' }] };
        let output = candidate;
        const adapter = new OpenAIChat({
            id, endpoint: input, allowed: () => true, consent: () => true,
            secrets: { get: k => { assert.equal(k, keyName(id, base)); return 'fake-test-key'; } },
            send: (url, options) => {
                assert.equal(url.href, base + (id === 'anthropic' ? 'messages' : 'chat/completions'));
                assert.equal(options.body.model, 'selected-model');
                selections.push(options.body.messages[0].content);
                const text = JSON.stringify(output);
                return id === 'anthropic' ? { stop_reason: 'end_turn', content: [{ type: 'text', text }] } :
                    { choices: [{ finish_reason: 'stop', message: { content: text } }] };
            }
        });
        const client = new DirectClient(adapter, 'selected-model');
        assert.deepEqual(await client.generateJson('Review selected lines as JSON', { operation: 'candidate' }), candidate);
        output = proposal;
        assert.deepEqual(JSON.parse(await client.generateCompletion('Return JSON edits', { operation: 'proposal' })), proposal);
        assert.equal(selections.length, 2);
        assert(client.requests.every(r => r.provider === id));
    });
}
test('custom and Azure approvals and credentials bind to the normalized API base', () => {
    const base = endpointFor('compatible', 'https://gateway.example/a');
    const other = endpointFor('compatible', 'https://gateway.example/b');
    const grants = [{ repository: '/repo', provider: 'compatible', endpoint: base }];
    const host = new ProviderHost({ workspace: { isTrusted: true, getConfiguration: () => ({
        inspect: () => ({ globalValue: grants })
    }) } }, {});
    assert(host.cloudAllowed('/repo', 'compatible', base));
    assert(!host.cloudAllowed('/repo', 'compatible', other));
    assert(!host.cloudAllowed('/repo', 'azure', base));
    assert.notEqual(keyName('compatible', base), keyName('compatible', other));
    for (const bad of ['http://example.com', 'https://127.0.0.1', 'https://[::1]', 'https://a:b@example.com', 'https://example.com/v1?key=test'])
        assert.throws(() => endpointFor('compatible', bad));
    assert.throws(() => endpointFor('azure', 'https://resource.openai.azure.com.example.org'));
});

test('outgoing credentials use the selected provider header and never follow redirects', async t => {
    const { EventEmitter } = require('node:events');
    let expected;
    t.mock.method(require('node:https'), 'request', (url, options, receive) => {
        assert.equal(url.href, expected.url);
        assert.deepEqual(options.headers, expected.headers);
        const request = new EventEmitter();
        request.end = () => {
            const response = new EventEmitter();
            Object.assign(response, { statusCode: 302, headers: { location: 'https://other.example/' }, destroy() {} });
            receive(response);
        };
        return request;
    });
    for (const [id, input, auth] of [
        ['anthropic', undefined, { 'x-api-key': 'fixture', 'anthropic-version': '2023-06-01' }],
        ['gemini', undefined, { Authorization: 'Bearer fixture' }],
        ['azure', 'https://resource.openai.azure.com', { 'api-key': 'fixture' }],
        ['compatible', 'https://gateway.example/v1/', { Authorization: 'Bearer fixture' }]
    ]) {
        const endpoint = endpointFor(id, input);
        expected = { url: endpoint + 'models', headers: { Accept: 'application/json', ...auth } };
        await assert.rejects(requestJson(new URL(expected.url), { provider: id, endpoint, key: 'fixture' }), /HTTP 302/);
        await assert.rejects(requestJson(new URL('https://other.example/v1/models'), { provider: id, endpoint, key: 'fixture' }), /denied/);
    }
});

test('provider picker grants only the selected Gemini repository and stores its key separately', async () => {
    const saved = new Map(), settings = new Map(), state = new Map();
    const host = new ProviderHost({
        ConfigurationTarget: { Global: 1 },
        workspace: { isTrusted: true, getConfiguration: () => ({
            inspect: k => ({ globalValue: settings.get(k) }),
            update: (k, v, scope) => { assert.equal(scope, 1); settings.set(k, v); }
        }) },
        window: {
            showQuickPick: items => items.find(item => item.id === 'gemini') || items[0],
            showInputBox: opts => { assert(opts.password); return 'fixture-key'; },
            showWarningMessage: (message, options) => { assert.match(options.detail, /generativelanguage\.googleapis\.com/); return 'Allow repository'; }
        }
    }, { secrets: { get: k => saved.get(k), store: (k,v) => saved.set(k,v) },
        workspaceState: { get: k => state.get(k), update: (k,v) => state.set(k,v) } });
    const original = host.adapter.bind(host);
    host.adapter = (...args) => {
        const adapter = original(...args);
        adapter.send = async (url, options) => {
            assert.equal(url.href, endpointFor('gemini') + 'models');
            assert.equal(options.key, 'fixture-key');
            return { data: [{ id: 'test-model' }] };
        };
        return adapter;
    };
    await host.configure('/repo');
    assert.deepEqual(host.selection(), { id: 'gemini', model: 'test-model' });
    assert.deepEqual([...saved.keys()], ['gcac.gemini.key']);
    await assert.rejects(host.client(host.selection(), '/other').getAvailableModels(), /policy prohibits/);
});
