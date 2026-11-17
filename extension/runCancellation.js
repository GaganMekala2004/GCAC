'use strict';
function createRunCancellation(upstream) {
    let cancelled = upstream?.isCancellationRequested === true;
    const listeners = new Set();
    function cancel() {
        if (cancelled) return;
        cancelled = true;
        for (const listener of [...listeners]) listener();
    }
    function subscribe(listener) {
        if (cancelled) listener(); else listeners.add(listener);
        return { dispose() { listeners.delete(listener); } };
    }
    const external = upstream?.onCancellationRequested ? upstream.onCancellationRequested(cancel)
        : upstream?.onCancel ? upstream.onCancel(cancel) : null;
    return { get isCancellationRequested() { return cancelled; }, onCancel: subscribe, onCancellationRequested: subscribe,
        cancel, dispose() { external?.dispose?.(); listeners.clear(); } };
}
module.exports = { createRunCancellation };
