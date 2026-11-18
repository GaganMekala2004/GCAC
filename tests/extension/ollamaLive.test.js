const { test } = require('node:test');
const assert = require('node:assert/strict');
const { DirectClient, Ollama } = require('../../extension/providers/direct');
test(
    'configured Ollama proposes a validated synthetic source repair',
    { skip: !process.env.GCAC_TEST_OLLAMA_MODEL },
    async () => {
        const client = new DirectClient(new Ollama(), process.env.GCAC_TEST_OLLAMA_MODEL);
        assert.equal((await client.getAvailableModels())[0].id, process.env.GCAC_TEST_OLLAMA_MODEL);
        const result = await client.generateJson(
            'Fix the synthetic source line by using textContent. Return JSON with only edits, an array of objects with oldText and newText strings. Source line: element.innerHTML = input;',
            {
                sourceCode: 'element.innerHTML = input;',
                filePath: 'example.js',
                operation: 'proposal'
            }
        );
        let candidate = 'element.innerHTML = input;';
        for (const edit of result.edits) {
            assert.equal(candidate.split(edit.oldText).length, 2);
            candidate = candidate.replace(edit.oldText, edit.newText);
        }
        assert.match(candidate, /^element\.textContent = input;?$/);
    }
);
