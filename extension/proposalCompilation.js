'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const { applyExactPatch } = require('./patchApplication');
const { resolveProfileForRepository } = require('./sandbox/toolchainProfiles');
const { EXECUTION_POLICY_VERSION, OPERATION_TYPES } = require('./sandbox/trustedExecutionGateway');

async function compileProposal({ repository, patchDiff, finding, gateway, runId, artifactDir, cancellationToken,
    cryptoMigrationContract, runTests, testOptions, minimumTests }) {
    const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'gcac-proposal-build-'));
    try {
        if (cryptoMigrationContract && (typeof finding.Location_Path !== 'string' || typeof runTests !== 'function')) {
            const error = new Error('PROPOSAL_COMPILER_UNAVAILABLE: Crypto candidate verification requires target-file metadata and a real test runner.');
            error.failureCategory = 'PROPOSAL_COMPILER_UNAVAILABLE';
            throw error;
        }
        fs.cpSync(repository, temp, { recursive: true, filter: source => !fs.lstatSync(source).isSymbolicLink() && !['.git', 'bin', 'TestResults'].includes(path.basename(source)) });
        applyExactPatch(temp, patchDiff);
        const profile = resolveProfileForRepository(temp, { Technology: 'dotnet' }, gateway.profilesPath);
        const result = await gateway.executeOperation({ runId,
            applicationId: finding.Application_Number || 'UNMAPPED-LOCAL', vulnerabilityId: finding.Vulnerability_ID,
            workspaceRef: temp, operation: OPERATION_TYPES.DOTNET_BUILD, toolchainProfileId: profile.profileId,
            requestedExecutable: 'dotnet', inputs: [], expectedOutputPaths: profile.outputArtifactPaths || [],
            extraArgs: [], policyVersion: EXECUTION_POLICY_VERSION, networkPolicy: 'NO_NETWORK',
            resourcePolicy: profile.runtimeLimits
        }, { originalWorkspaceRoot: temp, cancellationToken });
        const passed = result.executed === true && result.exitCode === 0 && !result.timedOut && !result.cancelled;
        const output = `${result.stdout || ''}\n${result.stderr || ''}`;
        const diagnostics = output.split('\n').filter(line => /\berror\s+(?:CS|MSB|NU)\d+/i.test(line)).slice(0, 8).join('\n');
        const evidence = { executed: result.executed === true, passed, exitCode: result.exitCode ?? null,
            command: result.command || 'dotnet build --no-restore', backendType: result.backendType,
            machineStatus: result.machineStatus, timedOut: !!result.timedOut, cancelled: !!result.cancelled,
            diagnostics: diagnostics || result.reason || result.summary || (passed ? 'Build succeeded.' : 'Candidate build did not complete.') };
        fs.mkdirSync(artifactDir, { recursive: true });
        fs.writeFileSync(path.join(artifactDir, 'proposal-compilation.json'), JSON.stringify(evidence, null, 2));
        if (!passed) {
            const error = new Error(`PROPOSAL_BUILD_FAILED: ${evidence.diagnostics}`);
            error.failureCategory = result.executed === true && !result.timedOut && !result.cancelled ? 'PATCH_INVALID' : (result.cancelled ? 'CANCELLED' : 'PROPOSAL_COMPILER_UNAVAILABLE');
            error.patchDiagnostic = { reasonCode: 'PROPOSAL_BUILD_FAILED', exitCode: evidence.exitCode };
            throw error;
        }
        if (cryptoMigrationContract) {
            const contract = await require('./cryptoContractValidation').validateCryptoContract({
                repository: temp, targetRelPath: finding.Location_Path, finding, runTests,
                testOptions: { ...testOptions, executionGateway: gateway, cancellationToken },
                artifactDir, minimumTests
            });
            if (!contract.executed || !contract.passed) {
                const error = new Error(`PROPOSAL_CRYPTO_CONTRACT_FAILED: ${contract.summary}`);
                error.failureCategory = contract.executed ? 'PATCH_INVALID' : 'PROPOSAL_COMPILER_UNAVAILABLE';
                error.patchDiagnostic = { reasonCode: 'PROPOSAL_CRYPTO_CONTRACT_FAILED' };
                throw error;
            }
            evidence.cryptoContract = { executed: true, passed: true, testsTotal: contract.testsTotal, testsPassed: contract.testsPassed };
            fs.writeFileSync(path.join(artifactDir, 'proposal-compilation.json'), JSON.stringify(evidence, null, 2));
        }
        return evidence;
    } finally { fs.rmSync(temp, { recursive: true, force: true }); }
}
module.exports = { compileProposal };
