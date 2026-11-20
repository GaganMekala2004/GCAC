// Entry for VS Code --extensionTestsPath against an isolated installed VSIX.
const assert = require('node:assert/strict');
const vscode = require('vscode');
exports.run = async function () {
    const extension = vscode.extensions.getExtension('gcac.gcac-vulnerability-remediation');
    assert(extension);
    assert.equal(extension.packageJSON.version, '2.0.5');
    assert.equal(typeof vscode.chat.createChatParticipant, 'function');
    await extension.activate();
    const commands = await vscode.commands.getCommands(true);
    for (const { command } of extension.packageJSON.contributes.commands)
        assert(commands.includes(command), command);
    for (const command of ['gcac.approveFinalGate', 'gcac.approveRemediation'])
        assert(commands.includes(command), command);
    await vscode.commands.executeCommand('gcac.openDashboard');
    console.log(
        'GCAC installed extension activated, commands registered, Chat API present and dashboard opened'
    );
};
