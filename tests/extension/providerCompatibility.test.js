const { test } = require('node:test');
const assert = require('node:assert/strict');
const { copilot, DEFAULT_PROVIDER } = require('../../extension/providers/copilot');
const manifest = require('../../package.json');

test('default handoff keeps participant, commands, payload and evidence boundary', async () => {
    const [participant] = manifest.contributes.chatParticipants;
    assert.equal(DEFAULT_PROVIDER, 'copilot');
    assert.equal(participant.name, 'vulnerability-orchestrator');
    assert.deepEqual(
        participant.commands.map((c) => c.name),
        ['remediate-vulnerability', 'approve', 'final-approve']
    );
    const query = '@vulnerability-orchestrator /remediate-vulnerability SCAN-DEMO';
    let args;
    assert.equal(
        await copilot.handoff(
            {
                executeCommand(...values) {
                    args = values;
                }
            },
            query
        ),
        'AWAITING_VERIFIED_RESULT'
    );
    assert.deepEqual(args, ['workbench.action.chat.open', { query, isPartialQuery: false }]);
    assert.equal(copilot.getCapabilities().nativeTelemetry, false);
});
