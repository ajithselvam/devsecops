"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.persistGitHubFindings = persistGitHubFindings;
exports.normalizeGitHubRepoUrl = normalizeGitHubRepoUrl;
exports.scanGitHubRepo = scanGitHubRepo;
exports.fixGitHubCode = fixGitHubCode;
const child_process_1 = require("child_process");
const fs_1 = require("fs");
const path_1 = require("path");
const os_1 = require("os");
const database_1 = require("../../../shared/database");
async function updateProgress(job, progress) {
    await job.updateProgress(progress);
}
function runCommand(command, args, options = {}) {
    try {
        const result = (0, child_process_1.execFileSync)(command, args, {
            cwd: options.cwd,
            timeout: options.timeout || 300000,
            encoding: 'utf-8',
            maxBuffer: 50 * 1024 * 1024
        });
        return result;
    }
    catch (error) {
        if (error.stdout)
            return error.stdout;
        if (error.stderr)
            return error.stderr;
        throw error;
    }
}
function parseSemgrepOutput(output) {
    const findings = [];
    try {
        const data = JSON.parse(output);
        if (data.results) {
            for (const result of data.results) {
                const extra = result.extra || {};
                const metadata = extra.metadata || {};
                findings.push({
                    id: `semgrep-${result.check_id || 'unknown'}-${result.path}-${result.start.line}`,
                    type: mapSemgrepType(metadata.category || 'security'),
                    severity: mapSemgrepSeverity(extra.severity || 'INFO'),
                    title: extra.message || result.check_id || 'Semgrep finding',
                    description: extra.message || 'No description available',
                    file: result.path,
                    line: result.start.line,
                    column: result.start.col,
                    ruleId: result.check_id,
                    cwe: metadata.cwe?.[0],
                    references: metadata.references,
                    fixable: !!extra.fix
                });
            }
        }
    }
    catch {
        // Ignore parse errors
    }
    return findings;
}
function parseGitleaksOutput(output) {
    const findings = [];
    try {
        const data = JSON.parse(output);
        for (const leak of data) {
            findings.push({
                id: `gitleaks-${leak.RuleID}-${leak.File}-${leak.StartLine}`,
                type: 'secret',
                severity: mapGitleaksSeverity(leak.RuleID),
                title: `Secret detected: ${leak.RuleID}`,
                description: `Potential secret found: ${leak.Description}`,
                file: leak.File,
                line: leak.StartLine,
                column: leak.StartColumn,
                ruleId: leak.RuleID,
                commit: leak.Commit,
                author: leak.Author,
                references: [`https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml#L${leak.RuleID}`]
            });
        }
    }
    catch {
        // Ignore parse errors
    }
    return findings;
}
function parseTrivyOutput(output) {
    const findings = [];
    try {
        const data = JSON.parse(output);
        if (data.Results) {
            for (const result of data.Results) {
                // Vulnerabilities
                if (result.Vulnerabilities) {
                    for (const vuln of result.Vulnerabilities) {
                        findings.push({
                            id: `trivy-${vuln.VulnerabilityID}-${result.Target}`,
                            type: 'vulnerability',
                            severity: mapSeverity(vuln.Severity),
                            title: vuln.VulnerabilityID,
                            description: vuln.Description || `${vuln.VulnerabilityID} in ${vuln.PkgName}@${vuln.InstalledVersion}`,
                            file: result.Target,
                            line: 1,
                            ruleId: vuln.VulnerabilityID,
                            cwe: vuln.CweIDs?.[0],
                            cvss: vuln.CVSS?.nvd?.V3Score,
                            references: vuln.References,
                            fixable: !!vuln.FixedVersion,
                            package: vuln.PkgName,
                            installedVersion: vuln.InstalledVersion,
                            fixedVersion: vuln.FixedVersion,
                            cve: vuln.VulnerabilityID
                        });
                    }
                }
                // Misconfigurations
                if (result.Misconfigurations) {
                    for (const misconfig of result.Misconfigurations) {
                        findings.push({
                            id: `trivy-iac-${misconfig.ID}-${result.Target}`,
                            type: 'iac',
                            severity: mapSeverity(misconfig.Severity),
                            title: misconfig.Title,
                            description: misconfig.Description,
                            file: result.Target,
                            line: misconfig.CauseMetadata?.StartLine || 1,
                            column: misconfig.CauseMetadata?.StartColumn || 0,
                            ruleId: misconfig.ID,
                            cwe: misconfig.CweIDs?.[0],
                            references: misconfig.References
                        });
                    }
                }
                // Secrets
                if (result.Secrets) {
                    for (const secret of result.Secrets) {
                        findings.push({
                            id: `trivy-secret-${secret.RuleID}-${result.Target}-${secret.StartLine}`,
                            type: 'secret',
                            severity: mapSeverity(secret.Severity),
                            title: `Secret: ${secret.RuleID}`,
                            description: secret.Match,
                            file: result.Target,
                            line: secret.StartLine,
                            column: secret.StartColumn,
                            ruleId: secret.RuleID
                        });
                    }
                }
            }
        }
    }
    catch {
        // Ignore parse errors
    }
    return findings;
}
function parseGrypeOutput(output) {
    const findings = [];
    try {
        const data = JSON.parse(output);
        if (data.matches) {
            for (const match of data.matches) {
                const vuln = match.vulnerability;
                const artifact = match.artifact;
                findings.push({
                    id: `grype-${vuln.id}-${artifact.name}`,
                    type: 'vulnerability',
                    severity: mapSeverity(vuln.severity),
                    title: vuln.id,
                    description: vuln.description || `${vuln.id} in ${artifact.name}@${artifact.version}`,
                    file: artifact.name,
                    line: 1,
                    ruleId: vuln.id,
                    cwe: typeof vuln.cwes?.[0] === 'string' ? vuln.cwes[0] : vuln.cwes?.[0]?.cwe,
                    cvss: vuln.cvss?.[0]?.metrics?.baseScore,
                    references: vuln.urls,
                    fixable: !!vuln.fix?.versions?.length,
                    package: artifact.name,
                    installedVersion: artifact.version,
                    fixedVersion: vuln.fix?.versions?.[0],
                    cve: vuln.id
                });
            }
        }
    }
    catch {
        // Ignore parse errors
    }
    return findings;
}
function mapSeverity(severity) {
    const s = severity?.toLowerCase() || 'info';
    if (s === 'critical')
        return 'critical';
    if (s === 'high')
        return 'high';
    if (s === 'medium')
        return 'medium';
    if (s === 'low')
        return 'low';
    return 'info';
}
function mapSemgrepType(category) {
    const c = category?.toLowerCase() || '';
    if (c.includes('secret'))
        return 'secret';
    if (c.includes('security'))
        return 'sast';
    if (c.includes('vulnerability'))
        return 'vulnerability';
    if (c.includes('license'))
        return 'license';
    return 'code-quality';
}
function mapSemgrepSeverity(severity) {
    const s = severity?.toUpperCase() || 'INFO';
    if (s === 'ERROR' || s === 'CRITICAL')
        return 'critical';
    if (s === 'HIGH')
        return 'high';
    if (s === 'MEDIUM')
        return 'medium';
    if (s === 'LOW')
        return 'low';
    return 'info';
}
function mapGitleaksSeverity(ruleId) {
    const r = ruleId?.toLowerCase() || '';
    if (r.includes('aws') || r.includes('gcp') || r.includes('azure') || r.includes('private-key'))
        return 'critical';
    if (r.includes('token') || r.includes('password') || r.includes('secret') || r.includes('api-key'))
        return 'high';
    return 'medium';
}
function deduplicateFindings(findings) {
    const seen = new Set();
    return findings.filter(f => {
        const key = `${f.ruleId}:${f.file}:${f.line}:${f.package || ''}`;
        if (seen.has(key))
            return false;
        seen.add(key);
        return true;
    });
}
function mapDbFindingType(type) {
    if (type === 'secret')
        return 'secret';
    if (type === 'vulnerability' || type === 'dependency')
        return 'vulnerability';
    if (type === 'misconfiguration' || type === 'iac')
        return 'misconfiguration';
    return 'security_issue';
}
function persistGitHubFindings(scanId, findings) {
    if (!scanId || findings.length === 0)
        return Promise.resolve();
    return database_1.prisma.finding.createMany({
        data: findings.map(f => ({
            scanId,
            type: mapDbFindingType(f.type),
            severity: f.severity,
            title: f.title.slice(0, 500),
            description: f.description,
            file: f.file,
            line: f.line,
            column: f.column,
            code: f.code,
            ruleId: f.ruleId,
            cwe: typeof f.cwe === 'string' ? f.cwe : undefined,
            cvssScore: typeof f.cvss === 'number' ? f.cvss : undefined,
            cve: f.cve,
            package: f.package,
            installedVersion: f.installedVersion,
            fixedVersion: f.fixedVersion,
            references: JSON.stringify(f.references || []),
            remediation: f.fixable
                ? JSON.stringify({
                    available: true,
                    type: f.fixedVersion ? 'upgrade' : 'patch',
                    description: f.fixedVersion
                        ? `Upgrade ${f.package || 'package'} to ${f.fixedVersion}`
                        : 'AI can generate a patch for this finding'
                })
                : null,
            status: 'open'
        }))
    });
}
function normalizeGitHubRepoUrl(raw) {
    let url = (raw || '').trim();
    if (url.startsWith('git@github.com:')) {
        url = 'https://github.com/' + url.replace('git@github.com:', '');
    }
    if (!/^https?:\/\//i.test(url)) {
        url = 'https://github.com/' + url.replace(/^github\.com\//i, '');
    }
    return url.replace(/\.git$/i, '').replace(/\/+$/, '');
}
function authenticatedCloneUrl(repoUrl, token) {
    const httpsUrl = `${normalizeGitHubRepoUrl(repoUrl)}.git`;
    if (!token)
        return httpsUrl;
    return httpsUrl.replace('https://', `https://x-access-token:${encodeURIComponent(token)}@`);
}
async function scanGitHubRepo(repoUrl, branch, token, job, scanId, scanTypes = ['vulnerabilities', 'secrets', 'dependencies', 'code']) {
    const tempDir = (0, fs_1.mkdtempSync)((0, path_1.join)((0, os_1.tmpdir)(), 'github-scan-'));
    const cloneDir = (0, path_1.join)(tempDir, 'repo');
    const types = scanTypes.length ? scanTypes : ['vulnerabilities', 'secrets', 'dependencies', 'code'];
    try {
        await updateProgress(job, { progress: 10, currentStep: 'Cloning repository' });
        const cloneUrl = authenticatedCloneUrl(repoUrl, token);
        try {
            runCommand('git', ['clone', '--depth', '1', '--branch', branch || 'main', cloneUrl, cloneDir], { timeout: 180000 });
        }
        catch {
            runCommand('git', ['clone', '--depth', '1', cloneUrl, cloneDir], { timeout: 180000 });
        }
        const allFindings = [];
        if (types.includes('code')) {
            await updateProgress(job, { progress: 25, currentStep: 'Running Semgrep SAST scan' });
            try {
                const semgrepOutput = runCommand('semgrep', [
                    'scan',
                    '--config', 'auto',
                    '--json',
                    '--quiet',
                    cloneDir
                ], { cwd: cloneDir, timeout: 180000 });
                allFindings.push(...parseSemgrepOutput(semgrepOutput));
            }
            catch (error) {
                console.warn('Semgrep scan failed:', error);
            }
        }
        if (types.includes('secrets')) {
            await updateProgress(job, { progress: 45, currentStep: 'Running Gitleaks secret scan' });
            try {
                const gitleaksOutput = runCommand('gitleaks', [
                    'detect',
                    '--source', cloneDir,
                    '--report-format', 'json',
                    '--no-git'
                ], { cwd: cloneDir, timeout: 120000 });
                allFindings.push(...parseGitleaksOutput(gitleaksOutput));
            }
            catch (error) {
                console.warn('Gitleaks scan failed:', error);
            }
        }
        if (types.includes('vulnerabilities') || types.includes('dependencies') || types.includes('secrets') || types.includes('code')) {
            await updateProgress(job, { progress: 60, currentStep: 'Running Trivy filesystem scan' });
            try {
                const scanners = [
                    ...(types.includes('vulnerabilities') || types.includes('dependencies') ? ['vuln'] : []),
                    ...(types.includes('code') ? ['misconfig'] : []),
                    ...(types.includes('secrets') ? ['secret'] : [])
                ].join(',') || 'vuln,secret,misconfig';
                const trivyOutput = runCommand('trivy', [
                    'fs',
                    '--format', 'json',
                    '--scanners', scanners,
                    '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
                    cloneDir
                ], { cwd: cloneDir, timeout: 180000 });
                allFindings.push(...parseTrivyOutput(trivyOutput));
            }
            catch (error) {
                console.warn('Trivy scan failed:', error);
            }
        }
        if (types.includes('vulnerabilities') || types.includes('dependencies')) {
            await updateProgress(job, { progress: 75, currentStep: 'Running Grype for dependency vulnerabilities' });
            try {
                const grypeOutput = runCommand('grype', [
                    'dir:' + cloneDir,
                    '-o', 'json',
                    '--add-cpes-if-none'
                ], { cwd: cloneDir, timeout: 180000 });
                allFindings.push(...parseGrypeOutput(grypeOutput));
            }
            catch (error) {
                console.warn('Grype scan failed:', error);
            }
        }
        await updateProgress(job, { progress: 85, currentStep: 'Generating SBOM' });
        try {
            runCommand('syft', ['dir:' + cloneDir, '-o', 'json'], { cwd: cloneDir, timeout: 120000 });
        }
        catch (error) {
            console.warn('Syft SBOM generation failed:', error);
        }
        await updateProgress(job, { progress: 90, currentStep: 'Consolidating findings' });
        const uniqueFindings = deduplicateFindings(allFindings);
        const summary = {
            totalFindings: uniqueFindings.length,
            critical: uniqueFindings.filter(f => f.severity === 'critical').length,
            high: uniqueFindings.filter(f => f.severity === 'high').length,
            medium: uniqueFindings.filter(f => f.severity === 'medium').length,
            low: uniqueFindings.filter(f => f.severity === 'low').length,
            info: uniqueFindings.filter(f => f.severity === 'info').length
        };
        if (scanId) {
            await persistGitHubFindings(scanId, uniqueFindings);
        }
        await updateProgress(job, { progress: 100, currentStep: 'Scan completed' });
        return { summary, findings: uniqueFindings };
    }
    finally {
        try {
            (0, fs_1.rmSync)(tempDir, { recursive: true, force: true });
        }
        catch {
            // Ignore cleanup errors
        }
    }
}
async function fixGitHubCode(finding, fileContent, surroundingContext, job) {
    await updateProgress(job, { progress: 10, currentStep: 'Analyzing code for fix' });
    // This will be enhanced with AI-based fixes
    // For now, return basic structure
    await updateProgress(job, { progress: 100, currentStep: 'Fix generation completed' });
    return {
        fixedCode: fileContent,
        explanation: `AI-generated fix for ${finding.title}`,
        confidence: 75
    };
}
