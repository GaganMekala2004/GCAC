// Explicit external transport fixture. Docker, git, the scanner and the engine remain real.
const { OpenAIChat } = require('../../extension/providers/openai');
function openaiCredentialFixture(defective, id = 'openai') {
    return new OpenAIChat({
        id,
        allowed: () => true,
        consent: () => true,
        secrets: { get: () => 'automated-contract-fixture' },
        send: async (url, options) => {
            if (url.pathname === '/v1/models') return { data: [{ id: 'contract-fixture' }] };
            const prompt = options.body.messages[0].content;
            let value;
            if (prompt.includes('Classification Agent'))
                value = {
                    cwe: 'CWE-798',
                    severity: 'High',
                    exploitability: 'Medium',
                    route: 'SpecializedAction',
                    strategy: 'Remove fallback',
                    attackVector: 'Source disclosure',
                    confidence: 90,
                    summary: 'Embedded credential fallback'
                };
            else if (prompt.includes('Root Cause Analysis (RCA) Agent'))
                value = {
                    dataFlow: 'Missing environment value selects a literal',
                    rootCause: 'Embedded fallback credential',
                    securityImpact: 'Source disclosure',
                    proposedFix: 'Reject missing configuration',
                    affectedLines: '5',
                    summary: 'Remove embedded fallback'
                };
            else if (prompt.includes('Return exactly this JSON shape')) {
                const match = prompt.match(/\?\? "(<GCAC_REDACTED_\d+>)"/);
                if (!match) throw Error('Expected a redacted fixture credential');
                value = {
                    edits: [
                        {
                            oldText: match[0],
                            newText: defective
                                ? '?? string.Empty'
                                : '?? throw new System.InvalidOperationException("Missing configuration")'
                        }
                    ]
                };
            } else
                value = {
                    rating: defective ? 'FAIL' : 'PASS',
                    summary: 'Authored test review fixture',
                    auditChecks: ['Test and scanner results are independently checked by the engine.']
                };
            if (id === 'anthropic') {
                if (url.href !== 'https://api.anthropic.com/v1/messages') throw Error('Incorrect Claude endpoint');
                return { stop_reason: 'end_turn', content: [{ type: 'text', text: JSON.stringify(value) }] };
            }
            return { choices: [{ finish_reason: 'stop', message: { content: JSON.stringify(value) } }] };
        }
    });
}
module.exports = { openaiCredentialFixture };
