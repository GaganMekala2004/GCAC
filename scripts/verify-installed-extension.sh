#!/usr/bin/env bash
set -euo pipefail
: "${VSCODE_CLI:=code}"
root=$(cd "$(dirname "$0")/.." && pwd)
profile=$(mktemp -d)
mkdir -p "$profile/probe" "$profile/workspace"
echo "Isolated VS Code profile and host logs: $profile"
cp "$root/tests/extension/installedHost.js" "$profile/probe/acceptance.js"
cat > "$profile/probe/package.json" <<'JSON'
{"name":"gcac-acceptance-probe","publisher":"gcac-test","version":"0.0.1","engines":{"vscode":"^1.90.0"},"main":"./extension.js"}
JSON
echo 'exports.activate = () => {};' > "$profile/probe/extension.js"
flags=(--user-data-dir "$profile/user" --extensions-dir "$profile/extensions")
"$VSCODE_CLI" "${flags[@]}" --install-extension "${1:-$root/out/gcac-2.0.0.vsix}"
"$VSCODE_CLI" "${flags[@]}" --disable-workspace-trust --disable-updates --skip-welcome \
    --extensionDevelopmentPath="$profile/probe" --extensionTestsPath="$profile/probe/acceptance.js" "$profile/workspace"
# The macOS launcher may return before the renderer flushes the extension test log.
for ((attempt=0; attempt<60; attempt++)); do
    if rg -F 'GCAC installed extension activated, commands registered, Chat API present and dashboard opened' "$profile/user/logs" 2>/dev/null; then
        exit 0
    fi
    sleep 1
done
echo "Installed extension test did not report completion. Inspect $profile/user/logs" >&2
exit 1
