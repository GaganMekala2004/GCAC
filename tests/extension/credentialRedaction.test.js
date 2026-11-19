'use strict';
const assert = require('assert');
const { createCredentialRedactor } = require('../../extension/credentialRedaction');
const { OutboundContextGate } = require('../../extension/outboundContextGate');
const { LlmClient } = require('../../extension/llmClient');
async function run() {
    // Synthetic credential shapes; never load repository credentials into tests/logs.
    const keys = ['sk_' + 'test_' + 'AbCd0123456789EfGh', 'rk_' + 'live_' + 'AbCd0123456789EfGh'];
    const source = JSON.stringify({ StripeKey: keys[0], OtherKey: keys[1] }, null, 2);
    const redactor = createCredentialRedactor();
    const clean = redactor.redact(source);
    for (const key of keys) assert(!clean.includes(key));
    assert.strictEqual(clean.split('\n').length, source.split('\n').length);
    assert.strictEqual(redactor.restore(clean), source);
    assert.strictEqual(redactor.redact(clean), clean);
    const gate = new OutboundContextGate();
    assert.strictEqual(gate.evaluate({ prompt: source, filePath: 'appsettings.json' }).allowed, false);
    assert.strictEqual(gate.evaluate({ prompt: clean, filePath: 'appsettings.json' }).allowed, true);
    const opaque = '"aBx9Cdy2EfGz78hJKlmN4OpQrStUv"';
    assert.strictEqual(gate.evaluate({ prompt: opaque }).decision.ruleId, 'SEC-HIGH-ENTROPY');
    const masked = redactor.redactSource(opaque);
    assert(!masked.includes(opaque.slice(1, -1)));
    assert.strictEqual(redactor.restore(masked), opaque);
    assert(gate.evaluate({ prompt: masked }).allowed);
    const client = new LlmClient();
    let inspected;
    client.getAvailableModels = async () => [];
    await assert.rejects(() => client.generateCompletion(source, { sourceCode: source, filePath: 'appsettings.json', outboundGate: { assertAllowed(request) { inspected = request; gate.assertAllowed(request); } } }), /Copilot is required/);
    assert.strictEqual(inspected.prompt, clean);
    assert.strictEqual(inspected.sourceCode, clean);
    await assert.rejects(() => client.generateCompletion('-----BEGIN PRIVATE KEY----- incomplete block', { filePath: 'source.cs' }), /OutboundContextGate BLOCKED/);
    console.log('Credential minimization: full known-key redaction, local patch reconstruction, unchanged fail-closed gate verified.');
}
module.exports = { run };
if (require.main === module) run().catch(e => { console.error(e); process.exitCode = 1; });
