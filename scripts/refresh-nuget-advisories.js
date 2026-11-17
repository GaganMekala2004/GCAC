'use strict';
const path = require('path');
const { refreshSnapshot, snapshotPath } = require('../extension/scanning/nugetAdvisories');
refreshSnapshot(snapshotPath(path.resolve(__dirname, '..'))).then(snapshot => {
    console.log(`NuGet advisory snapshot refreshed: ${Object.keys(snapshot.packages).length} packages; ${snapshot.pages.length} pages; ${snapshot.fetchedAt}`);
}).catch(error => { console.error(`NuGet advisory refresh failed: ${error.message}. Existing snapshot preserved.`); process.exitCode = 1; });
