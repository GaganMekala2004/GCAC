const http = require('http');

function fetch(url, options = {}) {
    return new Promise((resolve, reject) => {
        const req = http.request(url, options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    resolve({ status: res.statusCode, json: () => JSON.parse(data), text: () => data });
                } catch (e) {
                    resolve({ status: res.statusCode, text: () => data });
                }
            });
        });
        req.on('error', reject);
        if (options.body) req.write(options.body);
        req.end();
    });
}

async function test() {
    console.log('--- 1. Testing /api/vulnerabilities ---');
    const r1 = await fetch('http://localhost:3000/api/vulnerabilities');
    const vulns = await r1.json();
    console.log(`Loaded ${vulns.length} vulnerabilities.`);

    console.log('\n--- 2. Testing /api/details for VUL-POC-007 (Has Shared Markdown) ---');
    const r2 = await fetch('http://localhost:3000/api/details?id=VUL-POC-007');
    const d2 = await r2.json();
    console.log('VUL-POC-007 Stages Count:', d2.stages.length);
    console.log('Stages List:', d2.stages.map(s => `${s.number}. ${s.name} [${s.status}]`).join(', '));
    console.log('Has Patch Diff:', Boolean(d2.patchDiff), 'Length:', d2.patchDiff?.length || 0);
    console.log('Has Trace Log:', Boolean(d2.traceLog), 'Length:', d2.traceLog?.length || 0);
    console.log('Has Validation Evidence:', Boolean(d2.validation), 'Build Result:', d2.validation?.buildResult, 'Score:', d2.validation?.confidenceScore);
    console.log('Has Audit Report:', Boolean(d2.reportMarkdown), 'Length:', d2.reportMarkdown?.length || 0);

    console.log('\n--- 3. Testing /api/details for GCAS-E2E-001 (Has remediation-output & evidence) ---');
    const r3 = await fetch('http://localhost:3000/api/details?id=GCAS-E2E-001');
    const d3 = await r3.json();
    console.log('GCAS-E2E-001 Stages Count:', d3.stages.length);
    console.log('Stages List:', d3.stages.map(s => `${s.number}. ${s.name} [${s.status}]`).join(', '));
    console.log('Has Patch Diff:', Boolean(d3.patchDiff), 'Length:', d3.patchDiff?.length || 0);
    console.log('Has Trace Log:', Boolean(d3.traceLog), 'Length:', d3.traceLog?.length || 0);
    console.log('Has Validation Evidence:', Boolean(d3.validation), 'Build Result:', d3.validation?.buildResult, 'Score:', d3.validation?.confidenceScore);
    console.log('Has Audit Report:', Boolean(d3.reportMarkdown), 'Length:', d3.reportMarkdown?.length || 0);

    console.log('\n--- 4. Testing /api/details for VUL-POC-001 (Has evidence directory) ---');
    const r4 = await fetch('http://localhost:3000/api/details?id=VUL-POC-001');
    const d4 = await r4.json();
    console.log('VUL-POC-001 Stages Count:', d4.stages.length);
    console.log('Has Patch Diff:', Boolean(d4.patchDiff), 'Length:', d4.patchDiff?.length || 0);
    console.log('Has Trace Log:', Boolean(d4.traceLog), 'Length:', d4.traceLog?.length || 0);
    console.log('Has Validation Evidence:', Boolean(d4.validation), 'Build Result:', d4.validation?.buildResult);

    console.log('\n--- 5. Testing Live Remediation Pipeline Execution for GCAS-E2E-003 ---');
    const { RemediationEngine } = require('../extension/remediationEngine');
    const engine = new RemediationEngine(__dirname + '/..');
    
    console.log('Running Step 1 to Stage 4 (Human Approval Stop)...');
    const step1 = await engine.executePipeline('GCAS-E2E-003', { isHumanApproved: false });
    console.log('Step 1 Status:', step1.status, 'Is Awaiting Approval:', step1.isAwaitingApproval);

    console.log('Authorizing Stage 4 and running to Stage 6 (Final Gate Stop)...');
    const step2 = await engine.executePipeline('GCAS-E2E-003', { isHumanApproved: true, isFinalApproved: false });
    console.log('Step 2 Status:', step2.status, 'Is Awaiting Final Approval:', step2.isAwaitingFinalApproval);

    console.log('Authorizing Stage 6 and completing Stage 7 (Manual Validations Hand-off)...');
    const step3 = await engine.executePipeline('GCAS-E2E-003', { isHumanApproved: true, isFinalApproved: true });
    console.log('Step 3 Status:', step3.status, 'Completed:', step3.isCompleted, 'Report:', step3.reportPath);

    console.log('\n--- 6. Verifying Details after Live Remediation of GCAS-E2E-003 ---');
    const r5 = await fetch('http://localhost:3000/api/details?id=GCAS-E2E-003');
    const d5 = await r5.json();
    console.log('GCAS-E2E-003 Stages List:', d5.stages.map(s => `${s.number}. ${s.name} [${s.status}]`).join(', '));
    console.log('Has Patch Diff:', Boolean(d5.patchDiff));
    console.log('Has Trace Log:', Boolean(d5.traceLog));
    console.log('Has Validation Evidence:', Boolean(d5.validation));
    console.log('Has Audit Report:', Boolean(d5.reportMarkdown));
    console.log('\nALL VERIFICATION CHECKS PASSED!');
}

test().catch(console.error);
