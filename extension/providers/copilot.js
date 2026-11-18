'use strict';

// Native Chat owns its tools. Opening the participant only records a handoff.
const copilot = Object.freeze({
    id: 'copilot',
    getCapabilities() {
        return {
            interactiveHandoff: true,
            directInference: true,
            structuredOutput: false,
            nativeTelemetry: false,
            providerManagedTools: true,
            nativeCancellation: false
        };
    },
    async handoff(commands, query) {
        await commands.executeCommand('workbench.action.chat.open', { query, isPartialQuery: false });
        return 'AWAITING_VERIFIED_RESULT';
    }
});
module.exports = { copilot, DEFAULT_PROVIDER: copilot.id };
