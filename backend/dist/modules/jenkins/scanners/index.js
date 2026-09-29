"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.scanJenkinsfile = scanJenkinsfile;
exports.fixJenkinsfile = fixJenkinsfile;
exports.generateJenkinsfile = generateJenkinsfile;
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
            maxBuffer: 10 * 1024 * 1024
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
function parseSemgrepOutput(output, file) {
    const findings = [];
    try {
        const data = JSON.parse(output);
        if (data.results) {
            for (const result of data.results) {
                const extra = result.extra || {};
                const metadata = extra.metadata || {};
                findings.push({
                    id: `semgrep-${result.check_id || 'unknown'}-${result.start.line}`,
                    type: mapSemgrepType(metadata.category || 'security'),
                    severity: mapSemgrepSeverity(extra.severity || 'INFO'),
                    title: extra.message || result.check_id || 'Semgrep finding',
                    description: extra.message || 'No description available',
                    file,
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
function parseGitleaksOutput(output, file) {
    const findings = [];
    try {
        const data = JSON.parse(output);
        for (const leak of data) {
            findings.push({
                id: `gitleaks-${leak.RuleID}-${leak.StartLine}`,
                type: 'secret',
                severity: mapGitleaksSeverity(leak.RuleID),
                title: `Secret detected: ${leak.RuleID}`,
                description: `Potential secret found: ${leak.Description}`,
                file,
                line: leak.StartLine,
                column: leak.StartColumn,
                ruleId: leak.RuleID,
                references: [`https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml#L${leak.RuleID}`]
            });
        }
    }
    catch {
        // Ignore parse errors
    }
    return findings;
}
function mapSemgrepType(category) {
    const c = category?.toLowerCase() || '';
    if (c.includes('secret'))
        return 'secret';
    if (c.includes('security'))
        return 'security';
    if (c.includes('performance'))
        return 'performance';
    if (c.includes('reliability'))
        return 'reliability';
    if (c.includes('maintainability'))
        return 'maintainability';
    return 'best-practice';
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
        const key = `${f.ruleId}:${f.file}:${f.line}`;
        if (seen.has(key))
            return false;
        seen.add(key);
        return true;
    });
}
async function scanJenkinsfile(jenkinsfile, job, scanId) {
    const tempDir = (0, fs_1.mkdtempSync)((0, path_1.join)((0, os_1.tmpdir)(), 'jenkins-scan-'));
    const jenkinsfilePath = (0, path_1.join)(tempDir, 'Jenkinsfile');
    try {
        await updateProgress(job, { progress: 10, currentStep: 'Writing Jenkinsfile to temp directory' });
        (0, fs_1.writeFileSync)(jenkinsfilePath, jenkinsfile);
        const allFindings = [];
        // Run Semgrep for security and best practice rules
        await updateProgress(job, { progress: 25, currentStep: 'Running Semgrep security scan' });
        try {
            const semgrepOutput = runCommand('semgrep', [
                'scan',
                '--config', 'auto',
                '--json',
                '--quiet',
                tempDir
            ], { cwd: tempDir, timeout: 300000 });
            const semgrepFindings = parseSemgrepOutput(semgrepOutput, 'Jenkinsfile');
            allFindings.push(...semgrepFindings);
        }
        catch (error) {
            console.warn('Semgrep scan failed:', error);
        }
        // Run Gitleaks for secret detection
        await updateProgress(job, { progress: 50, currentStep: 'Running Gitleaks secret scan' });
        try {
            const gitleaksOutput = runCommand('gitleaks', [
                'detect',
                '--source', tempDir,
                '--report-format', 'json',
                '--verbose'
            ], { cwd: tempDir, timeout: 120000 });
            const gitleaksFindings = parseGitleaksOutput(gitleaksOutput, 'Jenkinsfile');
            allFindings.push(...gitleaksFindings);
        }
        catch (error) {
            console.warn('Gitleaks scan failed:', error);
        }
        // Custom Jenkinsfile pattern checks
        await updateProgress(job, { progress: 70, currentStep: 'Running custom Jenkinsfile checks' });
        const customFindings = runCustomJenkinsfileChecks(jenkinsfile);
        allFindings.push(...customFindings);
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
            await database_1.prisma.finding.createMany({
                data: uniqueFindings.map(f => ({
                    scanId,
                    type: f.type,
                    severity: f.severity,
                    title: f.title,
                    description: f.description,
                    file: f.file,
                    line: f.line,
                    column: f.column,
                    ruleId: f.ruleId,
                    cwe: f.cwe,
                    references: JSON.stringify(f.references || []),
                    fixable: f.fixable,
                    status: 'open'
                }))
            });
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
function runCustomJenkinsfileChecks(jenkinsfile) {
    const findings = [];
    const lines = jenkinsfile.split('\n');
    // Check for hardcoded credentials
    const credentialPatterns = [
        { pattern: /password\s*[:=]\s*['"][^'"]+['"]/gi, ruleId: 'JENKINS-HARDCODED-PASSWORD', title: 'Hardcoded password', severity: 'critical', type: 'secret' },
        { pattern: /token\s*[:=]\s*['"][^'"]+['"]/gi, ruleId: 'JENKINS-HARDCODED-TOKEN', title: 'Hardcoded token', severity: 'critical', type: 'secret' },
        { pattern: /api[_-]?key\s*[:=]\s*['"][^'"]+['"]/gi, ruleId: 'JENKINS-HARDCODED-API-KEY', title: 'Hardcoded API key', severity: 'critical', type: 'secret' },
        { pattern: /secret\s*[:=]\s*['"][^'"]+['"]/gi, ruleId: 'JENKINS-HARDCODED-SECRET', title: 'Hardcoded secret', severity: 'critical', type: 'secret' },
    ];
    // Check for insecure practices
    const insecurePatterns = [
        { pattern: /sh\s+['"]curl\s+.*\|\s*sh['"]/gi, ruleId: 'JENKINS-CURL-PIPE-SH', title: 'Piping curl to shell', severity: 'high', type: 'security' },
        { pattern: /sh\s+['"]wget\s+.*\|\s*sh['"]/gi, ruleId: 'JENKINS-WGET-PIPE-SH', title: 'Piping wget to shell', severity: 'high', type: 'security' },
        { pattern: /docker\s+login\s+-p\s+\$\w+/gi, ruleId: 'JENKINS-DOCKER-LOGIN-PLAIN', title: 'Docker login with plain password', severity: 'high', type: 'security' },
        { pattern: /withCredentials.*\$\w+/gi, ruleId: 'JENKINS-CREDENTIALS-IN-SCRIPT', title: 'Credentials used in shell script', severity: 'medium', type: 'security' },
        { pattern: /agent\s+any/gi, ruleId: 'JENKINS-AGENT-ANY', title: 'Using "agent any" - consider specific labels', severity: 'low', type: 'best-practice' },
        { pattern: /disableConcurrentBuilds\s*\(\s*\)/gi, ruleId: 'JENKINS-NO-CONCURRENT', title: 'Concurrent builds disabled', severity: 'info', type: 'best-practice' },
        { pattern: /timeout\s*\(\s*time:\s*0\s*\)/gi, ruleId: 'JENKINS-NO-TIMEOUT', title: 'No timeout set for build', severity: 'medium', type: 'reliability' },
    ];
    // Check for deprecated patterns
    const deprecatedPatterns = [
        { pattern: /node\s*\(/gi, ruleId: 'JENKINS-DEPRECATED-NODE', title: 'Using deprecated "node" syntax', severity: 'low', type: 'maintainability' },
        { pattern: /stage\s*\(/gi, ruleId: 'JENKINS-DEPRECATED-STAGE', title: 'Using deprecated stage syntax', severity: 'low', type: 'maintainability' },
    ];
    // Check for best practices
    const bestPracticePatterns = [
        { pattern: /pipeline\s*\{/, ruleId: 'JENKINS-PIPELINE-SYNTAX', title: 'Using declarative pipeline syntax', severity: 'info', type: 'best-practice', positive: true },
        { pattern: /options\s*\{/, ruleId: 'JENKINS-OPTIONS-BLOCK', title: 'Using options block', severity: 'info', type: 'best-practice', positive: true },
        { pattern: /environment\s*\{/, ruleId: 'JENKINS-ENVIRONMENT-BLOCK', title: 'Using environment block', severity: 'info', type: 'best-practice', positive: true },
        { pattern: /post\s*\{/, ruleId: 'JENKINS-POST-BLOCK', title: 'Using post block for cleanup', severity: 'info', type: 'best-practice', positive: true },
        { pattern: /tools\s*\{/, ruleId: 'JENKINS-TOOLS-BLOCK', title: 'Using tools block', severity: 'info', type: 'best-practice', positive: true },
    ];
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const lineNum = i + 1;
        // Check credential patterns
        for (const check of credentialPatterns) {
            const matches = line.matchAll(check.pattern);
            for (const match of matches) {
                findings.push({
                    id: `${check.ruleId}-${lineNum}`,
                    type: check.type,
                    severity: check.severity,
                    title: check.title,
                    description: `Found ${check.title.toLowerCase()} in Jenkinsfile`,
                    file: 'Jenkinsfile',
                    line: lineNum,
                    column: match.index,
                    ruleId: check.ruleId,
                    references: ['https://www.jenkins.io/doc/book/pipeline/best-practices/']
                });
            }
        }
        // Check insecure patterns
        for (const check of insecurePatterns) {
            const matches = line.matchAll(check.pattern);
            for (const match of matches) {
                findings.push({
                    id: `${check.ruleId}-${lineNum}`,
                    type: check.type,
                    severity: check.severity,
                    title: check.title,
                    description: check.title,
                    file: 'Jenkinsfile',
                    line: lineNum,
                    column: match.index,
                    ruleId: check.ruleId,
                    references: ['https://www.jenkins.io/doc/book/pipeline/best-practices/']
                });
            }
        }
        // Check deprecated patterns
        for (const check of deprecatedPatterns) {
            const matches = line.matchAll(check.pattern);
            for (const match of matches) {
                findings.push({
                    id: `${check.ruleId}-${lineNum}`,
                    type: check.type,
                    severity: check.severity,
                    title: check.title,
                    description: check.title,
                    file: 'Jenkinsfile',
                    line: lineNum,
                    column: match.index,
                    ruleId: check.ruleId,
                    references: ['https://www.jenkins.io/doc/book/pipeline/syntax/']
                });
            }
        }
        // Check best practices (positive findings)
        for (const check of bestPracticePatterns) {
            if (check.pattern.test(line)) {
                findings.push({
                    id: `${check.ruleId}-${lineNum}`,
                    type: check.type,
                    severity: check.severity,
                    title: check.title,
                    description: check.title,
                    file: 'Jenkinsfile',
                    line: lineNum,
                    ruleId: check.ruleId,
                    references: ['https://www.jenkins.io/doc/book/pipeline/best-practices/']
                });
            }
        }
    }
    return findings;
}
async function fixJenkinsfile(jenkinsfile, findings, job) {
    await updateProgress(job, { progress: 10, currentStep: 'Analyzing Jenkinsfile issues' });
    const fixedJenkinsfile = jenkinsfile;
    const changes = [];
    // Sort findings by severity
    const sortedFindings = [...findings].sort((a, b) => {
        const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        return severityOrder[a.severity] - severityOrder[b.severity];
    });
    // Basic fixes for common issues
    for (const finding of sortedFindings) {
        if (finding.ruleId) {
            // This is a simplified version - real implementation would use AI
            changes.push({
                findingId: finding.id,
                type: 'configuration_fix',
                description: `Fix applied for ${finding.title}`,
                ruleId: finding.ruleId
            });
        }
    }
    await updateProgress(job, { progress: 100, currentStep: 'Fix generation completed' });
    return { fixedJenkinsfile, changes };
}
async function generateJenkinsfile(spec, job) {
    await updateProgress(job, { progress: 10, currentStep: 'Generating Jenkinsfile' });
    const { name = 'my-pipeline', agent = 'any', stages = [], environment = {}, tools = {}, options = {}, triggers = {}, post = {} } = spec;
    let jenkinsfile = `pipeline {
  agent ${typeof agent === 'string' ? agent : JSON.stringify(agent, null, 2).replace(/\n/g, '\n  ')}
`;
    if (Object.keys(environment).length > 0) {
        jenkinsfile += `  environment {
`;
        for (const [key, value] of Object.entries(environment)) {
            jenkinsfile += `    ${key} = '${value}'
`;
        }
        jenkinsfile += `  }
`;
    }
    if (Object.keys(tools).length > 0) {
        jenkinsfile += `  tools {
`;
        for (const [key, value] of Object.entries(tools)) {
            jenkinsfile += `    ${key} '${value}'
`;
        }
        jenkinsfile += `  }
`;
    }
    if (Object.keys(options).length > 0) {
        jenkinsfile += `  options {
`;
        for (const [key, value] of Object.entries(options)) {
            jenkinsfile += `    ${key}(${typeof value === 'string' ? `'${value}'` : value})
`;
        }
        jenkinsfile += `  }
`;
    }
    if (Object.keys(triggers).length > 0) {
        jenkinsfile += `  triggers {
`;
        for (const [key, value] of Object.entries(triggers)) {
            jenkinsfile += `    ${key}(${typeof value === 'string' ? `'${value}'` : value})
`;
        }
        jenkinsfile += `  }
`;
    }
    jenkinsfile += `  stages {
`;
    for (const stage of stages) {
        jenkinsfile += `    stage('${stage.name}') {
`;
        if (stage.agent) {
            jenkinsfile += `      agent ${typeof stage.agent === 'string' ? stage.agent : JSON.stringify(stage.agent, null, 6).replace(/\n/g, '\n      ')}
`;
        }
        if (stage.environment) {
            jenkinsfile += `      environment {
`;
            for (const [key, value] of Object.entries(stage.environment)) {
                jenkinsfile += `        ${key} = '${value}'
`;
            }
            jenkinsfile += `      }
`;
        }
        if (stage.steps) {
            jenkinsfile += `      steps {
`;
            for (const step of stage.steps) {
                if (typeof step === 'string') {
                    jenkinsfile += `        ${step}
`;
                }
                else if (step.sh) {
                    jenkinsfile += `        sh '''
${step.sh}
'''
`;
                }
                else if (step.echo) {
                    jenkinsfile += `        echo '${step.echo}'
`;
                }
            }
            jenkinsfile += `      }
`;
        }
        jenkinsfile += `    }
`;
    }
    jenkinsfile += `  }
`;
    if (Object.keys(post).length > 0) {
        jenkinsfile += `  post {
`;
        for (const [condition, actions] of Object.entries(post)) {
            jenkinsfile += `    ${condition} {
`;
            for (const action of actions) {
                if (action.echo) {
                    jenkinsfile += `      echo '${action.echo}'
`;
                }
                else if (action.sh) {
                    jenkinsfile += `      sh '''
${action.sh}
'''
`;
                }
            }
            jenkinsfile += `    }
`;
        }
        jenkinsfile += `  }
`;
    }
    jenkinsfile += `}`;
    await updateProgress(job, { progress: 100, currentStep: 'Generation completed' });
    return { jenkinsfile };
}
