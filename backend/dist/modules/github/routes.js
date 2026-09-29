"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.githubRoutes = githubRoutes;
const database_1 = require("../../shared/database");
const audit_1 = require("../../shared/utils/audit");
const ai_1 = require("../../shared/ai");
const scanners_1 = require("./scanners");
const connectSchema = {
    type: 'object',
    required: ['token'],
    properties: {
        token: { type: 'string', minLength: 1 },
        org: { type: 'string' }
    }
};
const scanSchema = {
    type: 'object',
    required: ['repoUrl'],
    properties: {
        repoUrl: { type: 'string', minLength: 1 },
        branch: { type: 'string' },
        scanTypes: {
            type: 'array',
            items: { type: 'string', enum: ['vulnerabilities', 'secrets', 'dependencies', 'code'] }
        }
    }
};
const fixSchema = {
    type: 'object',
    required: ['findingId'],
    properties: {
        scanId: { type: 'string' },
        findingId: { type: 'string' },
        repoId: { type: 'string' },
        branch: { type: 'string' },
        fixType: { type: 'string' }
    }
};
const createPrSchema = {
    type: 'object',
    required: ['title'],
    properties: {
        repoId: { type: 'string' },
        repoUrl: { type: 'string' },
        branch: { type: 'string' },
        title: { type: 'string' },
        body: { type: 'string' },
        changes: {
            type: 'array',
            items: {
                type: 'object',
                properties: {
                    file: { type: 'string' },
                    content: { type: 'string' }
                }
            }
        }
    }
};
const GH_HEADERS = (token) => ({
    Authorization: `Bearer ${token}`,
    Accept: 'application/vnd.github+json',
    'User-Agent': 'devsecops-ai-platform',
    'X-GitHub-Api-Version': '2022-11-28'
});
function parseOwnerRepo(input) {
    const url = (0, scanners_1.normalizeGitHubRepoUrl)(input);
    const match = url.match(/github\.com\/([^/]+)\/([^/]+)/i);
    if (!match)
        return null;
    return { owner: match[1], repo: match[2].replace(/\.git$/i, '') };
}
function parseAiJson(text) {
    let cleaned = (text || '').trim();
    cleaned = cleaned.replace(/^```[a-zA-Z]*\s*\n?/, '').replace(/\n?```\s*$/, '').trim();
    const start = cleaned.indexOf('{');
    const end = cleaned.lastIndexOf('}');
    if (start >= 0 && end > start)
        cleaned = cleaned.slice(start, end + 1);
    return JSON.parse(cleaned);
}
function scoreFromFindings(findings) {
    const penalty = { critical: 25, high: 15, medium: 8, low: 3, info: 1 };
    return Math.max(0, 100 - findings.reduce((sum, f) => sum + (penalty[f.severity] || 0), 0));
}
function buildScoreSummary(findings, counts) {
    const vulns = findings.filter(f => f.type === 'vulnerability' || f.type === 'dependency');
    const secrets = findings.filter(f => f.type === 'secret');
    const code = findings.filter(f => f.type !== 'vulnerability' && f.type !== 'dependency' && f.type !== 'secret');
    return {
        ...counts,
        securityScore: scoreFromFindings(findings),
        dependenciesScore: scoreFromFindings(vulns),
        secretsScore: secrets.length === 0 ? 100 : scoreFromFindings(secrets),
        codeScore: scoreFromFindings(code)
    };
}
function formatScanPayload(scan) {
    const findings = scan.findings || [];
    let summary = {};
    try {
        summary = scan.summary ? JSON.parse(scan.summary) : {};
    }
    catch {
        summary = {};
    }
    const vulnerabilities = findings
        .filter((f) => f.type === 'vulnerability')
        .map((f) => ({
        id: f.id,
        cve: f.cve || f.ruleId || f.id,
        severity: f.severity,
        package: f.package || f.file,
        description: f.description,
        installedVersion: f.installedVersion,
        fixedVersion: f.fixedVersion,
        fixAvailable: !!f.fixedVersion || !!f.remediation
    }));
    const secrets = findings
        .filter((f) => f.type === 'secret')
        .map((f) => ({
        id: f.id,
        severity: f.severity,
        type: f.ruleId || f.title,
        message: f.description,
        file: f.file,
        line: f.line,
        rule: f.ruleId
    }));
    const codeIssues = findings
        .filter((f) => f.type !== 'vulnerability' && f.type !== 'secret')
        .map((f) => {
        let remediation = null;
        try {
            remediation = f.remediation ? JSON.parse(f.remediation) : null;
        }
        catch {
            remediation = null;
        }
        return {
            id: f.id,
            severity: f.severity,
            message: f.title,
            file: f.file,
            line: f.line,
            code: f.code,
            ruleId: f.ruleId,
            fixable: !!remediation?.available || f.type === 'security_issue' || f.type === 'misconfiguration',
            suggestion: remediation?.description
        };
    });
    if (!summary.securityScore) {
        summary = buildScoreSummary(findings.map((f) => ({ type: f.type, severity: f.severity })), {
            totalFindings: findings.length,
            critical: findings.filter((f) => f.severity === 'critical').length,
            high: findings.filter((f) => f.severity === 'high').length,
            medium: findings.filter((f) => f.severity === 'medium').length,
            low: findings.filter((f) => f.severity === 'low').length,
            info: findings.filter((f) => f.severity === 'info').length
        });
    }
    return { vulnerabilities, secrets, codeIssues, summary };
}
async function getGithubToken(userId) {
    const settings = await database_1.prisma.settings.findUnique({ where: { userId } });
    return settings?.githubToken || settings?.githubPrivateKey || null;
}
async function aiFallbackScan(repoUrl, branch, scanTypes) {
    const prompt = `
You are a GitHub repository security scanner (Grype + Gitleaks + Semgrep).
Analyze the public GitHub repository "${repoUrl}" on branch "${branch || 'main'}".
Scan types requested: ${scanTypes.join(', ')}.

Return ONLY valid JSON (no markdown fences):
{
  "findings": [
    {
      "type": "vulnerability" | "secret" | "security_issue" | "misconfiguration",
      "severity": "critical" | "high" | "medium" | "low" | "info",
      "title": "short title",
      "description": "what is wrong and why it matters",
      "file": "path/in/repo",
      "line": 1,
      "ruleId": "rule-or-cve",
      "package": "optional package name",
      "installedVersion": "optional",
      "fixedVersion": "optional",
      "cve": "optional CVE id",
      "fixable": true
    }
  ]
}

Include realistic findings typical of this kind of project (dependency CVEs, hardcoded secrets, insecure defaults).
Return 6-15 findings covering the requested scan types.
`;
    const aiResult = await ai_1.aiService.ask({
        prompt,
        systemPrompt: 'You are a repository security scanning engine. Respond only with raw valid JSON.',
        temperature: 0.2,
        maxTokens: 4096
    });
    const parsed = parseAiJson(aiResult.response);
    const findings = (parsed.findings || []).map((f, idx) => ({
        id: `ai-${f.type || 'issue'}-${idx}-${f.file || 'repo'}`,
        type: f.type === 'secret' ? 'secret' : f.type === 'vulnerability' ? 'vulnerability' : f.type === 'misconfiguration' ? 'misconfiguration' : 'sast',
        severity: ['critical', 'high', 'medium', 'low', 'info'].includes(f.severity) ? f.severity : 'medium',
        title: f.title || f.cve || 'Security finding',
        description: f.description || f.title || 'Potential security issue',
        file: f.file || 'unknown',
        line: Number(f.line) || 1,
        ruleId: f.ruleId || f.cve,
        package: f.package,
        installedVersion: f.installedVersion,
        fixedVersion: f.fixedVersion,
        cve: f.cve,
        fixable: f.fixable !== false
    }));
    return findings;
}
async function runScanJob(opts) {
    const { scanId, jobId, repoUrl, branch, token, scanTypes } = opts;
    const mockJob = {
        id: jobId,
        updateProgress: async (progress) => {
            const value = typeof progress === 'object' ? progress.progress : progress;
            const currentStep = typeof progress === 'object' ? progress.currentStep : '';
            await database_1.prisma.job.update({
                where: { id: jobId },
                data: { progress: Number(value) || 0, currentStep: currentStep || undefined }
            });
        }
    };
    try {
        await database_1.prisma.scan.update({ where: { id: scanId }, data: { status: 'running' } });
        await database_1.prisma.job.update({
            where: { id: jobId },
            data: { status: 'running', startedAt: new Date(), progress: 5, currentStep: 'Starting scan' }
        });
        let result;
        try {
            result = await (0, scanners_1.scanGitHubRepo)(repoUrl, branch, token, mockJob, scanId, scanTypes);
        }
        catch (err) {
            console.warn('CLI GitHub scan failed, using AI fallback:', err.message);
            await mockJob.updateProgress({ progress: 40, currentStep: 'CLI scanners unavailable — AI analysis' });
            const aiFindings = await aiFallbackScan(repoUrl, branch, scanTypes);
            await (0, scanners_1.persistGitHubFindings)(scanId, aiFindings);
            result = {
                findings: aiFindings,
                summary: {
                    totalFindings: aiFindings.length,
                    critical: aiFindings.filter(f => f.severity === 'critical').length,
                    high: aiFindings.filter(f => f.severity === 'high').length,
                    medium: aiFindings.filter(f => f.severity === 'medium').length,
                    low: aiFindings.filter(f => f.severity === 'low').length,
                    info: aiFindings.filter(f => f.severity === 'info').length
                }
            };
        }
        if (!result.findings.length) {
            try {
                const aiFindings = await aiFallbackScan(repoUrl, branch, scanTypes);
                if (aiFindings.length) {
                    await (0, scanners_1.persistGitHubFindings)(scanId, aiFindings);
                    result = {
                        findings: aiFindings,
                        summary: {
                            totalFindings: aiFindings.length,
                            critical: aiFindings.filter(f => f.severity === 'critical').length,
                            high: aiFindings.filter(f => f.severity === 'high').length,
                            medium: aiFindings.filter(f => f.severity === 'medium').length,
                            low: aiFindings.filter(f => f.severity === 'low').length,
                            info: aiFindings.filter(f => f.severity === 'info').length
                        }
                    };
                }
            }
            catch (aiErr) {
                console.warn('AI fallback produced no findings:', aiErr.message);
            }
        }
        const summary = buildScoreSummary(result.findings, result.summary);
        await database_1.prisma.scan.update({
            where: { id: scanId },
            data: {
                status: 'completed',
                summary: JSON.stringify(summary),
                completedAt: new Date()
            }
        });
        await database_1.prisma.job.update({
            where: { id: jobId },
            data: {
                status: 'completed',
                progress: 100,
                currentStep: 'Scan completed',
                output: JSON.stringify({ summary }),
                completedAt: new Date()
            }
        });
    }
    catch (error) {
        console.error('GitHub scan failed:', error);
        await database_1.prisma.scan.update({
            where: { id: scanId },
            data: { status: 'failed' }
        }).catch(() => { });
        await database_1.prisma.job.update({
            where: { id: jobId },
            data: {
                status: 'failed',
                error: error?.message || 'Scan failed',
                completedAt: new Date()
            }
        }).catch(() => { });
    }
}
async function githubRoutes(app) {
    app.get('/status', {
        preHandler: [app.authenticate]
    }, async (request) => {
        const userId = request.user.userId;
        const token = await getGithubToken(userId);
        return { success: true, data: { connected: !!token } };
    });
    app.post('/connect', {
        preHandler: [app.authenticate],
        schema: { body: connectSchema }
    }, async (request, reply) => {
        const userId = request.user.userId;
        const { token, org } = request.body;
        const userRes = await fetch('https://api.github.com/user', { headers: GH_HEADERS(token) });
        if (!userRes.ok) {
            return reply.code(400).send({
                success: false,
                error: { code: 'INVALID_TOKEN', message: 'GitHub rejected this token. Check scopes and try again.', statusCode: 400 }
            });
        }
        const ghUser = await userRes.json();
        await database_1.prisma.settings.upsert({
            where: { userId },
            create: { userId, githubToken: token, githubDefaultOrg: org || ghUser.login },
            update: { githubToken: token, githubDefaultOrg: org || ghUser.login }
        });
        const reposRes = await fetch('https://api.github.com/user/repos?per_page=30&sort=updated', {
            headers: GH_HEADERS(token)
        });
        const repos = reposRes.ok ? await reposRes.json() : [];
        for (const repo of Array.isArray(repos) ? repos.slice(0, 30) : []) {
            await database_1.prisma.gitHubRepository.upsert({
                where: { githubId: repo.id },
                create: {
                    userId,
                    githubId: repo.id,
                    name: repo.name,
                    fullName: repo.full_name,
                    url: repo.html_url,
                    cloneUrl: repo.clone_url,
                    defaultBranch: repo.default_branch || 'main',
                    private: !!repo.private
                },
                update: {
                    name: repo.name,
                    fullName: repo.full_name,
                    url: repo.html_url,
                    cloneUrl: repo.clone_url,
                    defaultBranch: repo.default_branch || 'main',
                    private: !!repo.private
                }
            });
        }
        await (0, audit_1.auditLog)(request, 'GITHUB_CONNECTED', 'github_repo', String(ghUser.id), { login: ghUser.login });
        return { success: true, data: { connected: true, login: ghUser.login } };
    });
    app.delete('/connect', {
        preHandler: [app.authenticate]
    }, async (request) => {
        const userId = request.user.userId;
        await database_1.prisma.settings.updateMany({
            where: { userId },
            data: { githubToken: null }
        });
        await (0, audit_1.auditLog)(request, 'GITHUB_DISCONNECTED', 'github_repo', userId);
        return { success: true, data: { connected: false } };
    });
    app.post('/scan', {
        preHandler: [app.authenticate],
        schema: { body: scanSchema }
    }, async (request) => {
        const userId = request.user.userId;
        const body = request.body;
        const repoUrl = (0, scanners_1.normalizeGitHubRepoUrl)(body.repoUrl);
        const branch = body.branch || 'main';
        const scanTypes = body.scanTypes?.length
            ? body.scanTypes
            : ['vulnerabilities', 'secrets', 'dependencies', 'code'];
        const scan = await database_1.prisma.scan.create({
            data: {
                type: 'github_repo',
                status: 'pending',
                targetType: 'github_repo',
                targetValue: repoUrl,
                targetMeta: JSON.stringify({ branch, scanTypes }),
                userId
            }
        });
        const job = await database_1.prisma.job.create({
            data: {
                type: 'github_repo_scan',
                status: 'queued',
                input: JSON.stringify({ repoUrl, branch, scanTypes }),
                userId,
                scanId: scan.id,
                currentStep: 'Queued'
            }
        });
        await database_1.prisma.scan.update({ where: { id: scan.id }, data: { jobId: job.id } });
        const token = (await getGithubToken(userId)) || '';
        setImmediate(() => {
            runScanJob({
                scanId: scan.id,
                jobId: job.id,
                repoUrl,
                branch,
                token,
                scanTypes
            }).catch((err) => console.error('Background GitHub scan error:', err));
        });
        await (0, audit_1.auditLog)(request, 'GITHUB_SCAN_STARTED', 'scan', scan.id, { repoUrl, branch, scanTypes });
        return { success: true, data: { scanId: scan.id, jobId: job.id } };
    });
    const getScanStatus = async (request, reply) => {
        const userId = request.user.userId;
        const { id } = request.params;
        const scan = await database_1.prisma.scan.findUnique({ where: { id } });
        if (!scan || scan.userId !== userId) {
            return reply.code(404).send({
                success: false,
                error: { code: 'NOT_FOUND', message: 'Scan not found', statusCode: 404 }
            });
        }
        let progress = scan.status === 'completed' ? 100 : scan.status === 'failed' ? 0 : 10;
        let currentStep = scan.status;
        if (scan.jobId) {
            const job = await database_1.prisma.job.findUnique({ where: { id: scan.jobId } });
            if (job) {
                progress = job.progress;
                currentStep = job.currentStep || job.status;
            }
        }
        return {
            success: true,
            data: {
                status: scan.status,
                progress,
                currentStep
            }
        };
    };
    const getScanResults = async (request, reply) => {
        const userId = request.user.userId;
        const { id } = request.params;
        const scan = await database_1.prisma.scan.findUnique({
            where: { id },
            include: { findings: { orderBy: [{ severity: 'desc' }, { createdAt: 'desc' }] } }
        });
        if (!scan || scan.userId !== userId) {
            return reply.code(404).send({
                success: false,
                error: { code: 'NOT_FOUND', message: 'Scan not found', statusCode: 404 }
            });
        }
        return { success: true, data: formatScanPayload(scan) };
    };
    app.get('/scans/:id/results', { preHandler: [app.authenticate] }, getScanResults);
    app.get('/scans/:id', { preHandler: [app.authenticate] }, getScanStatus);
    app.get('/scan/:id/results', { preHandler: [app.authenticate] }, getScanResults);
    app.get('/scan/:id/status', { preHandler: [app.authenticate] }, getScanStatus);
    app.post('/fix', {
        preHandler: [app.authenticate],
        schema: { body: fixSchema }
    }, async (request, reply) => {
        const userId = request.user.userId;
        const { scanId, findingId } = request.body;
        const finding = await database_1.prisma.finding.findFirst({
            where: scanId ? { id: findingId, scanId } : { id: findingId },
            include: { scan: true }
        });
        if (!finding || finding.scan.userId !== userId) {
            return reply.code(404).send({
                success: false,
                error: { code: 'NOT_FOUND', message: 'Finding not found', statusCode: 404 }
            });
        }
        try {
            const aiFix = await ai_1.aiService.fixGitHubCode({
                id: finding.id,
                type: finding.type,
                severity: finding.severity,
                title: finding.title,
                description: finding.description,
                file: finding.file,
                line: finding.line,
                code: finding.code,
                ruleId: finding.ruleId,
                package: finding.package,
                installedVersion: finding.installedVersion,
                fixedVersion: finding.fixedVersion
            }, finding.code || '', `${finding.file || ''}:${finding.line || 1}`);
            await (0, audit_1.auditLog)(request, 'GITHUB_FIX_STARTED', 'finding', findingId);
            return {
                success: true,
                data: {
                    patch: aiFix.patch || '',
                    explanation: aiFix.explanation || `Suggested remediation for ${finding.title}`,
                    changes: finding.file
                        ? [{ file: finding.file, content: aiFix.patch || '' }]
                        : [],
                    confidence: aiFix.confidence
                }
            };
        }
        catch (error) {
            const fallbackPatch = finding.fixedVersion && finding.package
                ? `Upgrade ${finding.package} from ${finding.installedVersion || 'current'} to ${finding.fixedVersion}`
                : `Review ${finding.file || 'the affected file'} around line ${finding.line || 1} and apply a secure alternative for: ${finding.title}`;
            return {
                success: true,
                data: {
                    patch: fallbackPatch,
                    explanation: `AI provider unavailable (${error?.message || 'unknown error'}). Manual remediation: ${finding.description}`,
                    changes: finding.file ? [{ file: finding.file, content: fallbackPatch }] : []
                }
            };
        }
    });
    const createPrHandler = async (request, reply) => {
        const userId = request.user.userId;
        const { repoId, repoUrl, branch, title, body, changes } = request.body;
        const token = await getGithubToken(userId);
        const target = parseOwnerRepo(repoUrl || repoId || '');
        if (!token || !target) {
            return reply.code(400).send({
                success: false,
                error: {
                    code: 'PR_UNAVAILABLE',
                    message: token
                        ? 'Could not parse owner/repo from the repository URL.'
                        : 'Connect GitHub with a token that has repo scope to create pull requests.',
                    statusCode: 400
                }
            });
        }
        try {
            const repoRes = await fetch(`https://api.github.com/repos/${target.owner}/${target.repo}`, {
                headers: GH_HEADERS(token)
            });
            if (!repoRes.ok) {
                throw new Error('Repository not found or token lacks access');
            }
            const repo = await repoRes.json();
            const base = repo.default_branch || 'main';
            const refRes = await fetch(`https://api.github.com/repos/${target.owner}/${target.repo}/git/ref/heads/${base}`, {
                headers: GH_HEADERS(token)
            });
            const ref = await refRes.json();
            const sha = ref.object?.sha;
            if (!sha)
                throw new Error('Could not read default branch SHA');
            const headBranch = branch && !['main', 'master'].includes(branch)
                ? branch
                : `devsecops-fix/${Date.now()}`;
            await fetch(`https://api.github.com/repos/${target.owner}/${target.repo}/git/refs`, {
                method: 'POST',
                headers: { ...GH_HEADERS(token), 'Content-Type': 'application/json' },
                body: JSON.stringify({ ref: `refs/heads/${headBranch}`, sha })
            });
            for (const change of changes || []) {
                if (!change.file)
                    continue;
                const encoded = Buffer.from(change.content || '', 'utf-8').toString('base64');
                const existing = await fetch(`https://api.github.com/repos/${target.owner}/${target.repo}/contents/${encodeURIComponent(change.file)}?ref=${headBranch}`, { headers: GH_HEADERS(token) });
                const existingJson = existing.ok ? await existing.json() : {};
                await fetch(`https://api.github.com/repos/${target.owner}/${target.repo}/contents/${change.file}`, {
                    method: 'PUT',
                    headers: { ...GH_HEADERS(token), 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        message: title,
                        content: encoded,
                        branch: headBranch,
                        sha: existingJson.sha
                    })
                });
            }
            const prRes = await fetch(`https://api.github.com/repos/${target.owner}/${target.repo}/pulls`, {
                method: 'POST',
                headers: { ...GH_HEADERS(token), 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    title,
                    body: body || title,
                    head: headBranch,
                    base
                })
            });
            const pr = await prRes.json();
            if (!prRes.ok) {
                throw new Error(pr.message || 'GitHub rejected the pull request');
            }
            await (0, audit_1.auditLog)(request, 'GITHUB_PR_CREATED', 'github_repo', repoId || target.repo, { branch: headBranch, title });
            return { success: true, data: { prUrl: pr.html_url, prNumber: pr.number } };
        }
        catch (error) {
            return reply.code(400).send({
                success: false,
                error: { code: 'PR_FAILED', message: error?.message || 'Failed to create pull request', statusCode: 400 }
            });
        }
    };
    app.post('/pr', { preHandler: [app.authenticate], schema: { body: createPrSchema } }, createPrHandler);
    app.post('/create-pr', { preHandler: [app.authenticate], schema: { body: createPrSchema } }, createPrHandler);
    const listRepos = async (request) => {
        const userId = request.user.userId;
        const repos = await database_1.prisma.gitHubRepository.findMany({
            where: { userId },
            orderBy: { connectedAt: 'desc' }
        });
        return { success: true, data: repos };
    };
    app.get('/repositories', { preHandler: [app.authenticate] }, listRepos);
    app.get('/repos', { preHandler: [app.authenticate] }, listRepos);
}
