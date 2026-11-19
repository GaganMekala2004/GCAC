'use strict';
const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns');
const { endpointFor } = require('./endpoints');
const { BlockList } = require('node:net');

const reserved = new BlockList();
for (const [address, prefix] of [
    ['0.0.0.0', 8],
    ['10.0.0.0', 8],
    ['100.64.0.0', 10],
    ['127.0.0.0', 8],
    ['169.254.0.0', 16],
    ['172.16.0.0', 12],
    ['192.0.0.0', 24],
    ['192.0.2.0', 24],
    ['192.88.99.0', 24],
    ['192.168.0.0', 16],
    ['198.18.0.0', 15],
    ['198.51.100.0', 24],
    ['203.0.113.0', 24],
    ['224.0.0.0', 4],
    ['240.0.0.0', 4]
])
    reserved.addSubnet(address, prefix);

function publicLookup(host, options, callback) {
    dns.lookup(host, { family: 4 }, (err, address) => {
        if (err) return callback(err);
        if (reserved.check(address)) return callback(new Error('Destination restricted'));
        callback(null, address, 4);
    });
}

async function requestJson(url, { body, key, provider, endpoint, cancellationToken, signal: upstream, timeout = 90000 } = {}) {
    const local = url.origin === 'http://127.0.0.1:11434';
    if (url.username || url.password) throw Error('Destination credentials denied');
    const base = provider ? endpointFor(provider, endpoint) : 'https://api.openai.com/v1/';
    const apiRequest = ['models', 'chat/completions', 'messages'].some(route => url.href === new URL(route, base).href);
    if (!local && url.origin !== 'https://api.osv.dev' && !apiRequest)
        throw Error('Destination denied');
    const signal = new AbortController();
    const abort = () => signal.abort();
    upstream?.addEventListener('abort', abort, { once: true });
    if (upstream?.aborted || cancellationToken?.isCancellationRequested) abort();
    const timer = setTimeout(() => signal.abort(), timeout);
    const subscription = cancellationToken?.onCancellationRequested(() => signal.abort());
    try {
        return await new Promise((resolve, reject) => {
            const headers = { Accept: 'application/json' };
            if (body) headers['Content-Type'] = 'application/json';
            if (key && !apiRequest)
                return reject(Error('Credential destination denied'));
            if (key && provider === 'anthropic') {
                headers['x-api-key'] = key;
                headers['anthropic-version'] = '2023-06-01';
            } else if (key && provider === 'azure') headers['api-key'] = key;
            else if (key) headers.Authorization = 'Bearer ' + key;
            const req = (local ? http : https).request(
                url,
                {
                    method: body ? 'POST' : 'GET',
                    headers,
                    signal: signal.signal,
                    agent: false,
                    family: 4,
                    lookup: local ? undefined : publicLookup
                },
                (res) => {
                    res.on('error', () => reject(Error('Provider response interrupted')));
                    if (res.statusCode !== 200 && res.statusCode !== 429) {
                        const error = Error('Provider HTTP ' + res.statusCode);
                        error.status = res.statusCode;
                        reject(error);
                        res.destroy();
                        return;
                    }
                    let bytes = 0;
                    const chunks = [];
                    res.on('data', (chunk) => {
                        bytes += chunk.length;
                        if (bytes > 1024 * 1024) {
                            reject(Error('Provider response too large'));
                            res.destroy();
                        } else chunks.push(chunk);
                    });
                    res.on('end', () => {
                        if (res.statusCode === 429) {
                            let quota = false;
                            try {
                                quota =
                                    JSON.parse(Buffer.concat(chunks).toString()).error?.code ===
                                    'insufficient_quota';
                            } catch {}
                            const error = Error(
                                quota
                                    ? 'Provider HTTP 429: quota exhausted'
                                    : 'Provider HTTP 429: rate limited'
                            );
                            error.status = 429;
                            return reject(error);
                        }
                        try {
                            resolve(JSON.parse(Buffer.concat(chunks).toString()));
                        } catch {
                            reject(Error('Invalid provider JSON'));
                        }
                    });
                }
            );
            req.on('error', (cause) => {
                const error = Error(
                    signal.signal.aborted
                        ? 'Provider request cancelled or timed out'
                        : 'Provider connection unavailable'
                );
                error.retryable =
                    !signal.signal.aborted && ['ECONNREFUSED', 'EAI_AGAIN'].includes(cause.code);
                reject(error);
            });
            req.end(body ? JSON.stringify(body) : undefined);
        });
    } finally {
        clearTimeout(timer);
        subscription?.dispose();
        upstream?.removeEventListener('abort', abort);
    }
}
module.exports = { requestJson };
