'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFile } = require('child_process');
const { promisify } = require('util');
const { createHash } = require('crypto');

const run = promisify(execFile);

function mavenCachePath(repository) {
    const root = fs.realpathSync(repository);
    const key = createHash('sha256').update(process.platform === 'win32' ? root.toLowerCase() : root).digest('hex');
    return path.join(os.homedir(), '.gcac', 'maven', key);
}

function readMavenSeed(file) {
    const xml = fs.readFileSync(file, 'utf8').replace(/<!--[\s\S]*?-->/g, '');
    if (/<(?:modules|profiles|dependencyManagement|extensions|repositories|pluginRepositories|build)\b/i.test(xml)) return null;
    const value = (block, tag) => new RegExp(`<${tag}>\\s*([^<]*?)\\s*</${tag}>`).exec(block || '')?.[1];
    const name = /^[A-Za-z0-9][A-Za-z0-9_.-]*$/;
    const fixedVersion = /^[0-9][A-Za-z0-9_.-]*$/;
    const entries = [];
    const makeEntry = (block, tag, allowManagedVersion = false) => {
        const groupId = value(block, 'groupId');
        const artifactId = value(block, 'artifactId');
        const version = value(block, 'version');
        const scope = value(block, 'scope');
        if (!name.test(groupId || '') || !name.test(artifactId || '') ||
            ((!allowManagedVersion || version) && (!fixedVersion.test(version || '') || /SNAPSHOT$/i.test(version))) ||
            (scope && !/^(compile|provided|runtime|test)$/.test(scope)) || /<(?:type|classifier|exclusions|systemPath)\b/.test(block)) return null;
        entries.push(`${groupId}:${artifactId}${version ? ':' + version : ' (parent-managed)'}`);
        return `<${tag}><groupId>${groupId}</groupId><artifactId>${artifactId}</artifactId>${version ? `<version>${version}</version>` : ''}${scope ? `<scope>${scope}</scope>` : ''}${tag === 'parent' ? '<relativePath/>' : ''}</${tag}>`;
    };
    const parent = /<parent>([\s\S]*?)<\/parent>/.exec(xml)?.[1];
    if (parent && (value(parent, 'groupId') !== 'org.springframework.boot' || value(parent, 'artifactId') !== 'spring-boot-starter-parent')) return null;
    const parentXml = parent ? makeEntry(parent, 'parent') : '';
    if (parent && !parentXml) return null;
    const dependencies = [...xml.matchAll(/<dependency>([\s\S]*?)<\/dependency>/g)].map(([, dep]) => makeEntry(dep, 'dependency', Boolean(parent)));
    if (dependencies.includes(null)) return null;
    const pom = `<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>${parentXml}<groupId>local.gcac</groupId><artifactId>cache-seed</artifactId><version>1.0.0</version><dependencies>${dependencies.join('')}</dependencies></project>`;
    return { pom, entries };
}

async function seedMavenCache(runtime, image, cacheRoot, pom) {
    const repo = path.join(cacheRoot, 'm2');
    fs.mkdirSync(repo, { recursive: true });
    const seed = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'gcac-maven-seed-'));
    try {
        fs.writeFileSync(path.join(seed, 'pom.xml'), pom);
        fs.writeFileSync(path.join(seed, 'settings.xml'), '<settings><mirrors><mirror><id>central</id><mirrorOf>*</mirrorOf><url>https://repo.maven.apache.org/maven2</url></mirror></mirrors></settings>');
        const source = path.join(seed, 'src', 'main', 'java');
        fs.mkdirSync(source, { recursive: true });
        fs.writeFileSync(path.join(source, 'CacheSeed.java'), 'final class CacheSeed {}\n');
        const user = process.getuid && process.getgid ? ['--user', `${process.getuid()}:${process.getgid()}`] : [];
        await run(runtime, ['run', '--rm', '--pull=never', '--cap-drop=ALL', '--security-opt=no-new-privileges', '--read-only',
            '--tmpfs', '/tmp:rw,nosuid,nodev', ...user, '-e', 'HOME=/tmp', '-e', 'MAVEN_CONFIG=/tmp/.m2',
            '-v', `${seed}:/seed:rw`, '-v', `${repo}:/packages:rw`, '-w', '/seed', image,
            'mvn', '-B', '-s', '/seed/settings.xml', '-Dmaven.repo.local=/packages', '-Duser.home=/tmp',
            '-DskipTests', '-ntp', 'test'], { timeout: 300000, windowsHide: true, maxBuffer: 4 * 1024 * 1024 });
    } finally {
        fs.rmSync(seed, { recursive: true, force: true });
    }
}

module.exports = { mavenCachePath, readMavenSeed, seedMavenCache };
