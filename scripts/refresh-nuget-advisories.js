'use strict';
const path = require('path');
const { refreshSnapshot, snapshotPath } = require('../extension/scanning/nugetAdvisories');
const fs = require('node:fs');
const workspace = process.argv[2] ? path.resolve(process.argv[2]) : path.resolve(__dirname, '..');
if (!fs.statSync(workspace, { throwIfNoEntry: false })?.isDirectory()) {
    console.error('Supply the path to an existing GCAC workspace folder.');
    process.exit(1);
}
refreshSnapshot(snapshotPath(workspace)).then(snapshot => {
    console.log(`NuGet advisory snapshot refreshed: ${Object.keys(snapshot.packages).length} packages; ${snapshot.pages.length} pages; ${snapshot.fetchedAt}`);
}).catch(error => { console.error(`NuGet advisory refresh failed: ${error.message}. Existing snapshot preserved.`); process.exitCode = 1; });
