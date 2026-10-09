const fs = require('fs');
const path = require('path');

/**
 * Robust CSV parser handling quotes, commas, and line breaks within fields
 */
function parseCsv(csvText) {
    const lines = [];
    let currentLine = [];
    let currentField = '';
    let inQuotes = false;

    for (let i = 0; i < csvText.length; i++) {
        const char = csvText[i];
        const nextChar = csvText[i + 1];

        if (char === '"') {
            if (inQuotes && nextChar === '"') {
                currentField += '"';
                i++; // Skip escaped quote
            } else {
                inQuotes = !inQuotes;
            }
        } else if (char === ',' && !inQuotes) {
            currentLine.push(currentField.trim());
            currentField = '';
        } else if ((char === '\r' || char === '\n') && !inQuotes) {
            if (char === '\r' && nextChar === '\n') {
                i++;
            }
            currentLine.push(currentField.trim());
            currentField = '';
            if (currentLine.some(f => f.length > 0)) {
                lines.push(currentLine);
            }
            currentLine = [];
        } else {
            currentField += char;
        }
    }

    if (currentField.length > 0 || currentLine.length > 0) {
        currentLine.push(currentField.trim());
        if (currentLine.some(f => f.length > 0)) {
            lines.push(currentLine);
        }
    }

    if (lines.length === 0) return [];

    const headers = lines[0].map(h => h.trim());
    const records = [];

    for (let i = 1; i < lines.length; i++) {
        const row = lines[i];
        if (row.length === 0 || (row.length === 1 && !row[0])) continue;
        const obj = {};
        headers.forEach((header, index) => {
            obj[header] = row[index] !== undefined ? row[index] : '';
        });
        records.push(obj);
    }

    return records;
}

/**
 * Serializes list of objects back to CSV format
 */
function serializeCsv(headers, records) {
    const escapeField = (val) => {
        if (val === null || val === undefined) return '';
        const str = String(val);
        if (str.includes(',') || str.includes('"') || str.includes('\n') || str.includes('\r')) {
            return `"${str.replace(/"/g, '""')}"`;
        }
        return str;
    };

    const headerLine = headers.map(escapeField).join(',');
    const dataLines = records.map(record => {
        return headers.map(h => escapeField(record[h] || '')).join(',');
    });

    return [headerLine, ...dataLines].join('\n') + '\n';
}

/**
 * Loads vulnerabilities from the CSV file
 */
function loadVulnerabilities(csvFilePath) {
    if (!fs.existsSync(csvFilePath)) {
        return [];
    }
    const content = fs.readFileSync(csvFilePath, 'utf-8');
    return parseCsv(content);
}

/**
 * Updates a single vulnerability row in the CSV file
 */
function updateVulnerabilityRow(csvFilePath, vulnerabilityId, updates) {
    if (!fs.existsSync(csvFilePath)) {
        throw new Error(`CSV file not found: ${csvFilePath}`);
    }

    const content = fs.readFileSync(csvFilePath, 'utf-8');
    const lines = [];
    let currentLine = [];
    let currentField = '';
    let inQuotes = false;

    for (let i = 0; i < content.length; i++) {
        const char = content[i];
        const nextChar = content[i + 1];

        if (char === '"') {
            if (inQuotes && nextChar === '"') {
                currentField += '"';
                i++;
            } else {
                inQuotes = !inQuotes;
            }
        } else if (char === ',' && !inQuotes) {
            currentLine.push(currentField);
            currentField = '';
        } else if ((char === '\r' || char === '\n') && !inQuotes) {
            if (char === '\r' && nextChar === '\n') {
                i++;
            }
            currentLine.push(currentField);
            currentField = '';
            if (currentLine.some(f => f.length > 0)) {
                lines.push(currentLine);
            }
            currentLine = [];
        } else {
            currentField += char;
        }
    }
    if (currentField.length > 0 || currentLine.length > 0) {
        currentLine.push(currentField);
        if (currentLine.some(f => f.length > 0)) {
            lines.push(currentLine);
        }
    }

    if (lines.length === 0) return false;

    const headers = lines[0].map(h => h.trim());
    const idIndex = headers.indexOf('Vulnerability_ID');
    if (idIndex === -1) return false;

    const records = [];
    let found = false;

    for (let i = 1; i < lines.length; i++) {
        const row = lines[i];
        const obj = {};
        headers.forEach((h, idx) => {
            obj[h] = row[idx] !== undefined ? row[idx] : '';
        });

        if (obj['Vulnerability_ID'] === vulnerabilityId) {
            Object.assign(obj, updates);
            found = true;
        }
        records.push(obj);
    }

    if (found) {
        const newCsvContent = serializeCsv(headers, records);
        fs.writeFileSync(csvFilePath, newCsvContent, 'utf-8');
    }

    return found;
}

module.exports = {
    parseCsv,
    serializeCsv,
    loadVulnerabilities,
    updateVulnerabilityRow
};
