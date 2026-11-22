'use strict';
// Conservative source-pattern recipes, used only after model correction fails.
// Every result still passes scope, compiler, review, test and scanner gates.
function dotnetRepairProposal({ sourceCode, cryptoMigrationContract }) {
    if (cryptoMigrationContract?.acknowledged && cryptoMigrationContract.legacyData === 'NONE') {
        const method = sourceCode.match(/public byte\[\] Encrypt\(byte\[\] data, byte\[\] key, byte\[\] iv\)\s*\{\s*using var des = DES\.Create\(\);\s*using var encryptor = des\.CreateEncryptor\(key, iv\);\s*return encryptor\.TransformFinalBlock\(data, 0, data\.Length\);\s*\}/);
        if (method) return JSON.stringify({ edits: [{ oldText: method[0], newText: `public byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
    {
        System.ArgumentNullException.ThrowIfNull(data);
        if (key == null || key.Length != 32) throw new System.ArgumentException("A 32-byte AES key is required.", nameof(key));
        if (iv == null || iv.Length != 12) throw new System.ArgumentException("A unique 12-byte nonce is required.", nameof(iv));
        var payload = new byte[29 + data.Length];
        payload[0] = 1;
        iv.CopyTo(payload, 1);
        using var aes = new System.Security.Cryptography.AesGcm(key, 16);
        aes.Encrypt(iv, data, System.MemoryExtensions.AsSpan(payload, 29), System.MemoryExtensions.AsSpan(payload, 13, 16));
        return payload;
    }` }] });
    }
    const sql = sourceCode.match(/(^[ \t]*)string ([A-Za-z_]\w*) = "(SELECT \* FROM [A-Za-z_]\w* WHERE )([A-Za-z_]\w*) = '" \+ ([A-Za-z_]\w*\.[A-Za-z_]\w*) \+ "' AND ([A-Za-z_]\w*) = " \+ ([A-Za-z_]\w*\.[A-Za-z_]\w*);\r?\n[ \t]*using var ([A-Za-z_]\w*) = new SqlCommand\(\2\);/m);
    if (sql) {
        const [, indent, query, prefix, firstField, firstValue, secondField, secondValue, command] = sql;
        return JSON.stringify({ edits: [{ oldText: sql[0], newText: [
            `string ${query} = "${prefix}${firstField} = @${firstField} AND ${secondField} = @${secondField}";`,
            `using var ${command} = new SqlCommand(${query});`,
            `${command}.Parameters.AddWithValue("@${firstField}", ${firstValue});`,
            `${command}.Parameters.AddWithValue("@${secondField}", ${secondValue});`
        ].map(line => indent + line).join('\n') }] });
    }
    const ping = sourceCode.match(/^(\s*)(\w+)\.StartInfo\.FileName = "sh";\r?\n[ \t]*\2\.StartInfo\.Arguments = "-c \\"ping -c 1 " \+ (\w+) \+ "\\"";/m);
    if (ping) {
        const [, indent, processName, host] = ping;
        const lines = [
            `if (System.Uri.CheckHostName(${host}) == System.UriHostNameType.Unknown || ${host}.StartsWith("-"))`,
            '    return BadRequest("Invalid host.");',
            `${processName}.StartInfo.FileName = "ping";`,
            `${processName}.StartInfo.ArgumentList.Add("-c");`,
            `${processName}.StartInfo.ArgumentList.Add("1");`,
            `${processName}.StartInfo.ArgumentList.Add(${host});`
        ];
        return JSON.stringify({ edits: [{ oldText: ping[0], newText: lines.map(line => indent + line).join('\n') }] });
    }
    const command = sourceCode.match(/(^[ \t]*)Process\.Start\("cmd\.exe", \$"\/c ([A-Za-z0-9_.-]+\.bat) \{([A-Za-z_]\w*)\}"\);/m);
    if (command && !/\breceiptProcessStartInfo\b/.test(sourceCode)) {
        const [, indent, script, argument] = command;
        return JSON.stringify({ edits: [{ oldText: command[0], newText: [
            `if (${argument} == null || !System.Text.RegularExpressions.Regex.IsMatch(${argument}, @"\u005cA[A-Za-z0-9_-]{1,64}\u005cz"))`,
            `    throw new System.ArgumentException("The identifier must contain 1-64 letters, digits, underscores or hyphens.", nameof(${argument}));`,
            'var receiptProcessStartInfo = new ProcessStartInfo { FileName = "cmd.exe", UseShellExecute = false };',
            'receiptProcessStartInfo.ArgumentList.Add("/d");',
            'receiptProcessStartInfo.ArgumentList.Add("/c");',
            `receiptProcessStartInfo.ArgumentList.Add("${script}");`,
            `receiptProcessStartInfo.ArgumentList.Add(${argument});`,
            'Process.Start(receiptProcessStartInfo);'
        ].map(line => indent + line).join('\n') }] });
    }
    return null;
}
// Only call with a target verified against the resolved graph and advisory cache.
function nugetRepairProposal({ sourceCode, packageName, currentVersion, upgrade }) {
    if (!upgrade || !/^[A-Za-z0-9_.-]+$/.test(packageName || '') ||
        !/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(upgrade.version || '') ||
        /<!--|<!DOCTYPE|<Import\b|\bCondition\s*=|ManagePackageVersionsCentrally/i.test(sourceCode)) return null;
    const references = [...sourceCode.matchAll(/<PackageReference\b[^>]*\/\s*>/gi)];
    // Expanded references and central/conditional ownership require separate handling.
    if ((sourceCode.match(/<PackageReference\b/gi) || []).length !== references.length) return null;
    const matches = references.filter(ref => ref[0].match(/\bInclude\s*=\s*["']([^"']+)["']/i)?.[1].toLowerCase() === packageName.toLowerCase());
    if (matches.length === 1 && !upgrade.transitive) {
        const oldText = matches[0][0];
        const version = /\bVersion\s*=\s*(["'])([^"']+)\1/i.exec(oldText);
        if (!version || version[2] !== currentVersion) return null;
        const newText = oldText.slice(0, version.index) + version[0].replace(currentVersion, upgrade.version) + oldText.slice(version.index + version[0].length);
        return JSON.stringify({ edits: [{ oldText, newText }] });
    }
    if (matches.length || !upgrade.transitive || /<PackageReference\b[^>]*\bUpdate\s*=/i.test(sourceCode)) return null;
    const endings = [...sourceCode.matchAll(/^[ \t]*<\/Project\s*>[ \t]*(?=\r?$)/gm)];
    if (endings.length !== 1) return null;
    const oldText = endings[0][0];
    const eol = sourceCode.includes('\r\n') ? '\r\n' : '\n';
    const indent = sourceCode.match(/^([ \t]+)<(?:PropertyGroup|ItemGroup)\b/m)?.[1] || '  ';
    const newText = [indent + '<ItemGroup>', indent + indent + '<PackageReference Include="' + packageName + '" Version="' + upgrade.version + '" />', indent + '</ItemGroup>', oldText].join(eol);
    return JSON.stringify({ edits: [{ oldText, newText }] });
}
module.exports = { dotnetRepairProposal, nugetRepairProposal };
