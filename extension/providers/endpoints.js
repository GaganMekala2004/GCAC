'use strict';
const { isIP } = require('node:net');

const providers = {
    openai: { label: 'OpenAI API', base: 'https://api.openai.com/v1/' },
    anthropic: { label: 'Anthropic Claude', base: 'https://api.anthropic.com/v1/' },
    gemini: { label: 'Google Gemini', base: 'https://generativelanguage.googleapis.com/v1beta/openai/' },
    azure: { label: 'Azure OpenAI' },
    compatible: { label: 'Custom OpenAI-compatible API' }
};

function endpointFor(id, input) {
    if (!Object.hasOwn(providers, id)) throw Error('Unknown external provider');
    if (providers[id].base) return providers[id].base;
    let url;
    try { url = new URL(input); } catch { throw Error('Enter the full public HTTPS API base URL'); }
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash ||
        isIP(url.hostname) || !/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i.test(url.hostname) ||
        /(?:^|\.)(?:localhost|local|internal)$/i.test(url.hostname))
        throw Error('Use a public HTTPS hostname without embedded credentials, query or fragment');
    if (id === 'azure' && (!/^[a-z0-9-]+\.(?:openai\.azure\.com|services\.ai\.azure\.com)$/.test(url.hostname) ||
        url.port || !/^\/(?:openai\/v1\/?)?$/.test(url.pathname)))
        throw Error('Enter the Azure resource URL, optionally ending in /openai/v1/');
    url.pathname = id === 'azure' ? '/openai/v1/' : url.pathname.replace(/\/?$/, '/');
    return url.href;
}

function keyName(id, base) {
    return providers[id].base ? 'gcac.' + id + '.key' : 'gcac.' + id + '.' + base + '.key';
}
module.exports = { providers, endpointFor, keyName };
