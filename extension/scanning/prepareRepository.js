'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const { promisify } = require('util');
const { assertPathWithinWorkspace } = require('../pathUtils');
const { discoverEnvironment } = require('../sandbox/environmentDiscovery');
const { resolveProfileForRepository, assertProfileProvisioned } = require('../sandbox/toolchainProfiles');
const { inspectDotnetProjects, runBaselineTests } = require('../testRunner');
const { DotnetSecurityScanner } = require('./adapters/dotnetSecurityScanner');
const { NuGetAuditScanner } = require('./adapters/nugetAuditScanner');
const { snapshotPath, readSnapshot, refreshSnapshot } = require('./nugetAdvisories');
const { resolveDotnetProjectFile } = require('./dotnetProjectLocator');
const { mavenCachePath, readMavenSeed, seedMavenCache } = require('./prepareMaven');

const run = promisify(execFile);

function readPackageSeeds(target, projects) {
    const seeds = new Map();
    let unresolved = 0;
    for (const project of projects) {
        const file = assertPathWithinWorkspace(project, target);
        if (!file || !fs.lstatSync(file).isFile()) continue;
        const xml = fs.readFileSync(file, 'utf8').replace(/<!--[\s\S]*?-->/g, '');
        for (const [, attributes, content] of xml.matchAll(/<PackageReference\b([^>]*?)(?:\/\s*>|>([\s\S]*?)<\/PackageReference\s*>)/gi)) {
            const name = /(?:^|\s)Include\s*=\s*(["'])([^"']+)\1/i.exec(attributes)?.[2];
            const version = /(?:^|\s)Version\s*=\s*(["'])([^"']+)\1/i.exec(attributes)?.[2]
                || /<Version>\s*([^<]+?)\s*<\/Version>/i.exec(content || '')?.[1];
            if (/^[a-z0-9][a-z0-9_.-]{0,99}$/i.test(name || '') && /^\d+(?:\.\d+){1,3}(?:-[0-9a-z.-]+)?$/i.test(version || '')) {
                seeds.set(`${name.toLowerCase()}@${version.toLowerCase()}`, { name, version });
            } else {
                unresolved++;
            }
        }
    }
    return { packages: [...seeds.values()], unresolved };
}

async function seedPublicPackages(runtime, profile, packages) {
    const cache = path.resolve(process.env.NUGET_PACKAGES || path.join(os.homedir(), '.nuget', 'packages'));
    fs.mkdirSync(cache, { recursive: true });
    const seed = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'gcac-nuget-seed-'));
    try {
        // Generate one independent graph per package version. Only validated names
        // and versions enter this workspace. Repository files never enter this container.
        const framework = `net${Number.parseInt(profile.toolchainVersion, 10)}.0`;
        const projects = packages.map(({ name, version }, index) => {
            const folder = path.join(seed, String(index));
            fs.mkdirSync(folder);
            fs.writeFileSync(path.join(folder, 'Seed.csproj'), `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>${framework}</TargetFramework></PropertyGroup><ItemGroup><PackageReference Include="${name}" Version="[${version}]" /></ItemGroup></Project>`);
            return `/seed/${index}/Seed.csproj`;
        });
        fs.writeFileSync(path.join(seed, 'Seed.proj'), `<Project><Target Name="Restore"><MSBuild Projects="${projects.join(';')}" Targets="Restore" /></Target></Project>`);
        fs.writeFileSync(path.join(seed, 'NuGet.Config'), '<configuration><packageSources><clear/><add key="nuget.org" value="https://api.nuget.org/v3/index.json" /></packageSources></configuration>');
        const user = process.getuid && process.getgid ? ['--user', `${process.getuid()}:${process.getgid()}`] : [];
        await run(runtime, ['run', '--rm', '--pull=never', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--read-only', '--tmpfs', '/tmp:rw,exec', ...user, '-e', 'HOME=/tmp', '-e', 'DOTNET_CLI_HOME=/tmp',
            '-v', `${seed}:/seed:rw`, '-v', `${cache}:/packages:rw`, '-w', '/seed', profile.imageRef,
            'dotnet', 'msbuild', 'Seed.proj', '-t:Restore', '-p:RestoreConfigFile=/seed/NuGet.Config',
            '-p:RestorePackagesPath=/packages', '-p:NuGetAudit=false', '-nologo'], { timeout: 180000, windowsHide: true });
    } finally {
        fs.rmSync(seed, { recursive: true, force: true });
    }
}

async function prepareRepository(workspaceRoot, target, { report, selectPackages, approveMaven, extensionRoot = workspaceRoot }) {
    const project = resolveDotnetProjectFile(target, target);
    const pom = assertPathWithinWorkspace('pom.xml', target);
    const isMaven = !project && pom && fs.existsSync(pom);
    if (!project && !isMaven) return ['Automatic setup currently supports .NET and repositories with a root Maven pom.xml.'];
    const envReport = discoverEnvironment({ workspaceRoot: extensionRoot, useCache: false });
    if (!envReport.sandboxAvailable) return ['Start Docker Desktop in Linux container mode or an approved Podman machine, then retry.'];
    const runtime = envReport.containers[envReport.selectedRuntime].binaryPath;
    const technology = isMaven ? 'java-maven' : 'dotnet';
    const profile = resolveProfileForRepository(project || target, { Technology: technology });
    assertProfileProvisioned(profile);
    report(`Checking the ${profile.profileId} SDK image`);
    try {
        await run(runtime, ['image', 'inspect', profile.imageRef], { timeout: 15000, windowsHide: true });
    } catch {
        await run(runtime, ['pull', profile.imageRef], { timeout: 300000, windowsHide: true });
    }

    const messages = [`SDK image ready (${profile.profileId}).`];
    if (isMaven) {
        const seed = readMavenSeed(pom);
        if (!seed) messages.push('This Maven project requires a pre-provisioned cache. Automatic downloads support simple public dependency declarations and the Spring Boot starter parent.');
        if (seed && await approveMaven?.(seed.entries)) {
            report('Preparing the Maven Central cache');
            try {
                await seedMavenCache(runtime, profile.imageRef, mavenCachePath(target), seed.pom);
                messages.push('Maven Central dependencies prepared in the repository cache.');
            } catch (error) {
                const detail = (error.stdout || error.stderr || '').split(/\r?\n/).find(line => line.startsWith('[ERROR]'));
                messages.push(`Maven cache preparation failed. ${detail || 'Check Maven Central connectivity.'}`);
            }
        }
        report('Checking Maven tests in the offline sandbox');
        const baseline = await runBaselineTests({ Technology: technology }, workspaceRoot, { workingDirectory: target, envReport });
        messages.push(baseline.passed ? `Baseline passed (${baseline.testsPassed}/${baseline.testsTotal} tests).`
            : `Baseline needs attention. ${baseline.rootError || baseline.reason || baseline.summary}`);
        if (!fs.existsSync(path.join(target, 'src', 'test'))) messages.push('This checkout has no standard Maven test sources under src/test. Commit real tests before starting remediation.');
        if (!envReport.scannersAndSbom.codeqlInstalled) messages.push('Optional CodeQL scanner needs installation from the Scans view.');
        return messages;
    }
    const { appProjects, testProjects } = inspectDotnetProjects(target);
    const { packages, unresolved } = readPackageSeeds(target, [...appProjects, ...testProjects]);
    if (unresolved) messages.push(`${unresolved} package reference(s) require an existing cache or an approved feed because the version is indirect or unpinned.`);
    const selected = packages.length ? await selectPackages(packages) : [];
    if (selected.length) {
        report('Preparing the NuGet package cache');
        try {
            await seedPublicPackages(runtime, profile, selected);
            messages.push('Selected NuGet packages restored to the local cache.');
        } catch (error) {
            const detail = (error.stdout || error.stderr || '').split(/\r?\n/).find(line => /\berror\s+NU\d+/i.test(line));
            messages.push(`Public package restore failed. ${detail?.trim() || 'Check Docker network access and the selected package versions.'}`);
        }
    }

    const advisories = snapshotPath(workspaceRoot);
    try {
        try { readSnapshot(advisories); }
        catch {
            report('Refreshing public NuGet advisories');
            await refreshSnapshot(advisories);
        }
    } catch (error) {
        messages.push(`NuGet advisories unavailable. ${error.message}`);
    }

    const scanOptions = { envReport, refreshAdvisories: false, repoContext: { repositoryRoot: target } };
    for (const [label, scanner] of [['.NET analysis', new DotnetSecurityScanner()], ['NuGet audit', new NuGetAuditScanner()]]) {
        report(`Checking ${label} in the offline sandbox`);
        const result = await scanner.scan(workspaceRoot, target, scanOptions);
        messages.push(`${label} · ${result.status}${result.errors?.length ? ` — ${result.errors[0]}` : ''}`);
    }

    if (testProjects.length) {
        report('Checking the baseline in the offline sandbox');
        const baseline = await runBaselineTests({ Technology: 'dotnet' }, workspaceRoot, { workingDirectory: target, envReport });
        messages.push(baseline.passed
            ? `Baseline passed (${baseline.testsPassed}/${baseline.testsTotal} tests).`
            : `Baseline blocked. ${baseline.rootError || baseline.reason || baseline.summary}`);
    } else {
        messages.push('Baseline blocked. Add a test project with real tests to the repository solution and commit it before starting remediation.');
    }
    if (!envReport.scannersAndSbom.codeqlInstalled) messages.push('Optional CodeQL scanner needs installation from the Scans view.');
    return messages;
}

module.exports = { prepareRepository, readPackageSeeds };
