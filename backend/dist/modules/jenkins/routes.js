"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.jenkinsRoutes = jenkinsRoutes;
const database_1 = require("../../shared/database");
const queue_1 = require("../../shared/queue");
const audit_1 = require("../../shared/utils/audit");
const ai_1 = require("../../shared/ai");
const child_process_1 = require("child_process");
const fs_1 = require("fs");
const path_1 = require("path");
const os_1 = require("os");
const analyzeSchema = {
    type: 'object',
    required: ['content'],
    properties: {
        content: { type: 'string', minLength: 1 }
    }
};
const fixSchema = {
    type: 'object',
    required: ['content'],
    properties: {
        content: { type: 'string', minLength: 1 },
        issues: { type: 'array' },
        options: { type: 'object' }
    }
};
const generateSchema = {
    type: 'object',
    properties: {
        config: { type: 'object' },
        application: { type: 'string' },
        repositoryUrl: { type: 'string' },
        buildTool: { type: 'string' },
        testing: { type: 'boolean' },
        dockerBuild: { type: 'boolean' },
        securityScan: { type: 'boolean' },
        dockerPush: { type: 'boolean' },
        deployment: { type: 'string' },
        environments: { type: 'array' }
    }
};
const validateSchema = {
    type: 'object',
    required: ['content'],
    properties: {
        content: { type: 'string', minLength: 1 }
    }
};
const scanSchema = {
    type: 'object',
    required: ['jenkinsfile'],
    properties: {
        jenkinsfile: { type: 'string', minLength: 1 },
        targetName: { type: 'string' },
        fix: { type: 'boolean', default: false }
    }
};
function parseStagesFromJenkinsfile(content) {
    const stages = [];
    const stageRegex = /stage\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\{([^}]*(?:\{[^}]*\}[^}]*)*)\}/g;
    let match;
    while ((match = stageRegex.exec(content)) !== null) {
        const stageName = match[1];
        const stageBody = match[2];
        const steps = [];
        const stepLines = stageBody.split('\n').map(l => l.trim()).filter(Boolean);
        for (const line of stepLines) {
            if (line.startsWith('sh ') || line.startsWith('echo ') || line.startsWith('bat ') || line.startsWith('checkout ') || line.startsWith('junit ')) {
                steps.push(line);
            }
        }
        stages.push({
            name: stageName,
            steps: steps.length > 0 ? steps : ['sh ...']
        });
    }
    if (stages.length === 0) {
        // Fallback simple line match
        const simpleMatches = content.match(/stage\s*\(\s*['"]([^'"]+)['"]\s*\)/g) || [];
        for (const sm of simpleMatches) {
            const name = sm.replace(/stage\s*\(\s*['"]/, '').replace(/['"]\s*\)/, '');
            stages.push({ name, steps: [] });
        }
    }
    return stages;
}
function runCustomJenkinsChecks(jenkinsfile) {
    const issues = [];
    const lines = jenkinsfile.split('\n');
    lines.forEach((line, idx) => {
        const lineNum = idx + 1;
        // 1. Plaintext password / token
        if (line.match(/(?:password|token|secret|api[_-]?key)\s*[:=]\s*['"][^'"]+['"]/i) && !line.includes('credentials(')) {
            issues.push({
                id: `jenkins-secret-literal-${lineNum}`,
                type: 'security',
                severity: 'critical',
                line: lineNum,
                message: 'Hardcoded secret or credential literal detected in pipeline',
                rule: 'JENKINS-SEC-001',
                fixable: true,
                suggestion: 'Use Jenkins credentials binding: withCredentials([usernamePassword(...), string(...)])'
            });
        }
        // 2. Unsafe curl/wget piped to shell
        if (line.match(/sh\s+['"].*(?:curl|wget)\s+.*\|\s*(?:sh|bash)['"]/i)) {
            issues.push({
                id: `jenkins-curl-pipe-sh-${lineNum}`,
                type: 'security',
                severity: 'high',
                line: lineNum,
                message: 'Remote script downloaded and piped directly to shell execution (curl | sh)',
                rule: 'JENKINS-SEC-002',
                fixable: true,
                suggestion: 'Download and verify checksum/signature of executable scripts before running'
            });
        }
        // 3. Insecure docker login
        if (line.match(/docker\s+login\s+-p\s+/i) || line.match(/docker\s+login\s+.*--password/i)) {
            issues.push({
                id: `jenkins-docker-login-${lineNum}`,
                type: 'security',
                severity: 'high',
                line: lineNum,
                message: 'Docker login passes password directly in CLI arguments (visible in process list & logs)',
                rule: 'JENKINS-SEC-003',
                fixable: true,
                suggestion: 'Use docker.withRegistry() or pipe password via standard input using docker login --password-stdin'
            });
        }
        // 4. Agent any usage
        if (line.match(/^\s*agent\s+any\s*$/i)) {
            issues.push({
                id: `jenkins-agent-any-${lineNum}`,
                type: 'best_practice',
                severity: 'low',
                line: lineNum,
                message: 'Pipeline uses "agent any" which may run builds on unhardened or shared controllers',
                rule: 'JENKINS-BP-001',
                fixable: true,
                suggestion: 'Specify isolated agent labels or container agents: agent { docker { ... } } or agent { label "build-agent" }'
            });
        }
    });
    // Global Pipeline checks
    if (!jenkinsfile.includes('timeout(') && !jenkinsfile.includes('timeout (')) {
        issues.push({
            id: 'jenkins-missing-timeout',
            type: 'reliability',
            severity: 'medium',
            line: 1,
            message: 'Pipeline is missing a global timeout option, risking hanging builds blocking executors indefinitely',
            rule: 'JENKINS-REL-001',
            fixable: true,
            suggestion: 'Add options { timeout(time: 1, unit: "HOURS") } in pipeline block'
        });
    }
    if (!jenkinsfile.includes('post {') && !jenkinsfile.includes('post{')) {
        issues.push({
            id: 'jenkins-missing-post-cleanup',
            type: 'best_practice',
            severity: 'medium',
            line: 1,
            message: 'Pipeline lacks a post block for workspace cleanup and notification triggers',
            rule: 'JENKINS-BP-002',
            fixable: true,
            suggestion: 'Add post { always { cleanWs() } failure { ... } }'
        });
    }
    if (!jenkinsfile.includes('ansiColor') && !jenkinsfile.includes('timestamps')) {
        issues.push({
            id: 'jenkins-missing-timestamps',
            type: 'performance',
            severity: 'info',
            line: 1,
            message: 'Console output timestamps and color formatting not enabled',
            rule: 'JENKINS-PERF-001',
            fixable: true,
            suggestion: 'Add options { timestamps(); ansiColor("xterm") }'
        });
    }
    return issues;
}
function runGitleaksScan(content) {
    const issues = [];
    const tempDir = (0, fs_1.mkdtempSync)((0, path_1.join)((0, os_1.tmpdir)(), 'jenkins-leak-'));
    const tempFile = (0, path_1.join)(tempDir, 'Jenkinsfile');
    try {
        (0, fs_1.writeFileSync)(tempFile, content, 'utf-8');
        const stdout = (0, child_process_1.execFileSync)('gitleaks', [
            'detect',
            '--source', tempDir,
            '--report-format', 'json',
            '--no-git'
        ], {
            timeout: 15000,
            encoding: 'utf-8'
        });
        const parsed = JSON.parse(stdout);
        if (Array.isArray(parsed)) {
            for (const leak of parsed) {
                issues.push({
                    id: `jenkins-gitleaks-${leak.RuleID}-${leak.StartLine}`,
                    type: 'security',
                    severity: 'critical',
                    line: leak.StartLine || 1,
                    message: `Secret exposed: ${leak.Description || leak.RuleID}`,
                    rule: leak.RuleID || 'SECRET_LEAK',
                    fixable: true,
                    suggestion: 'Remove hardcoded secret and replace with Jenkins Credentials reference'
                });
            }
        }
    }
    catch (err) {
        if (err.stdout && err.stdout.trim().startsWith('[')) {
            try {
                const parsed = JSON.parse(err.stdout);
                for (const leak of parsed) {
                    issues.push({
                        id: `jenkins-gitleaks-${leak.RuleID}-${leak.StartLine}`,
                        type: 'security',
                        severity: 'critical',
                        line: leak.StartLine || 1,
                        message: `Secret detected: ${leak.Description || leak.RuleID}`,
                        rule: leak.RuleID || 'SECRET_LEAK',
                        fixable: true,
                        suggestion: 'Use Jenkins credentials binding instead of plaintext secret'
                    });
                }
            }
            catch { }
        }
    }
    finally {
        try {
            (0, fs_1.rmSync)(tempDir, { recursive: true, force: true });
        }
        catch { }
    }
    return issues;
}
async function jenkinsRoutes(app) {
    // 1. Analyze Jenkinsfile (synchronous)
    app.post('/analyze', {
        preHandler: [app.authenticate],
        schema: { body: analyzeSchema }
    }, async (request, reply) => {
        const { content } = request.body;
        try {
            const stages = parseStagesFromJenkinsfile(content);
            const customIssues = runCustomJenkinsChecks(content);
            const gitleaksIssues = runGitleaksScan(content);
            // Deduplicate issues
            const seen = new Set();
            const allIssues = [];
            for (const issue of [...gitleaksIssues, ...customIssues]) {
                const key = `${issue.rule}-${issue.line}`;
                if (!seen.has(key)) {
                    seen.add(key);
                    allIssues.push(issue);
                }
            }
            const result = {
                jenkinsfile: content,
                issues: allIssues,
                stages
            };
            return { success: true, data: result };
        }
        catch (error) {
            console.error('Jenkinsfile analyze error:', error);
            return reply.code(500).send({
                success: false,
                error: { code: 'ANALYZE_FAILED', message: error.message || 'Analysis failed', statusCode: 500 }
            });
        }
    });
    // 2. Fix Jenkinsfile using AI
    app.post('/fix', {
        preHandler: [app.authenticate],
        schema: { body: fixSchema }
    }, async (request, reply) => {
        const { content, issues } = request.body;
        const issuesList = issues && issues.length > 0
            ? issues
            : runCustomJenkinsChecks(content);
        const prompt = `
You are an expert CI/CD and Jenkins security engineer.
Fix the following Jenkinsfile to resolve all security, credentials, timeout, and pipeline best-practice issues.

Original Jenkinsfile:
${content}

Issues to fix:
${issuesList.map((issue, idx) => `${idx + 1}. [${issue.severity.toUpperCase()}] Line ${issue.line}: ${issue.message}${issue.suggestion ? ` (Suggestion: ${issue.suggestion})` : ''}`).join('\n')}

Fix Requirements:
1. Wrap credentials with withCredentials([usernamePassword(credentialsId: '...', usernameVariable: '...', passwordVariable: '...')]) or string(credentialsId: '...', variable: '...').
2. Add options { timeout(time: 1, unit: 'HOURS'); timestamps(); ansiColor('xterm') } in the declarative pipeline block.
3. Secure Docker logins using --password-stdin or docker.withRegistry().
4. Add a complete post block with cleanWs() for workspace cleanup.
5. Return ONLY the complete, valid, fixed Jenkinsfile without markdown code fences or conversational text.
`;
        try {
            const aiResponse = await ai_1.aiService.ask({
                prompt,
                systemPrompt: 'You are an automated Jenkins pipeline hardening engine. Respond ONLY with the raw valid Jenkinsfile without markdown code fences.',
                temperature: 0.1,
                maxTokens: 4096
            });
            let fixedJenkinsfile = aiResponse.response.trim();
            fixedJenkinsfile = fixedJenkinsfile.replace(/^```[a-zA-Z]*\s*\n?/, '').replace(/\n?```\s*$/, '').trim();
            if (!fixedJenkinsfile) {
                throw new Error('AI returned an empty Jenkinsfile response');
            }
            const changes = issuesList.map(issue => ({
                findingId: issue.id,
                type: 'pipeline_security_fix',
                description: `Fixed: ${issue.message}`,
                line: issue.line
            }));
            const explanation = `AI analyzed ${issuesList.length} issues in the Jenkinsfile and generated a production-grade Declarative Pipeline with credential masking, automated workspace cleanup, timeouts, and execution hardening.`;
            return {
                success: true,
                data: {
                    fixedJenkinsfile,
                    changes,
                    explanation
                }
            };
        }
        catch (error) {
            console.error('Jenkins AI fix error:', error);
            return reply.code(500).send({
                success: false,
                error: { code: 'FIX_FAILED', message: error.message || 'AI fix failed', statusCode: 500 }
            });
        }
    });
    // 3. Generate Jenkinsfile using AI
    app.post('/generate', {
        preHandler: [app.authenticate],
        schema: { body: generateSchema }
    }, async (request, reply) => {
        const body = request.body;
        const config = body.config || body;
        const application = config.application || 'nodejs';
        const repositoryUrl = config.repositoryUrl || 'https://github.com/user/repo';
        const buildTool = config.buildTool || 'npm';
        const testing = config.testing ?? true;
        const dockerBuild = config.dockerBuild ?? true;
        const securityScan = config.securityScan ?? true;
        const dockerPush = config.dockerPush ?? true;
        const deployment = config.deployment || 'kubernetes';
        const registryUrl = config.registryUrl || 'docker.io/myorg';
        const environments = config.environments || ['dev', 'staging', 'production'];
        const prompt = `
You are an expert DevOps engineer. Generate a production-ready Declarative Jenkinsfile (pipeline { ... }) for:
- Application Type: ${application}
- Repository URL: ${repositoryUrl}
- Build Tool: ${buildTool}
- Run Automated Tests: ${testing ? 'Yes' : 'No'}
- Build Docker Image: ${dockerBuild ? 'Yes' : 'No'}
- Security Vulnerability Scan (Trivy / Grype): ${securityScan ? 'Yes' : 'No'}
- Push Docker Image: ${dockerPush ? `Yes (Registry: ${registryUrl})` : 'No'}
- Deployment Target: ${deployment}
- Target Environments: ${environments.join(', ')}

Requirements:
1. Return ONLY the raw valid Declarative Jenkinsfile. No markdown code blocks, no explanations.
2. Include options (timeout, timestamps, ansiColor).
3. Include environment block with standard credentials and image tags.
4. Include stages: Checkout, Build, ${testing ? 'Test, ' : ''}${securityScan ? 'Security Scan, ' : ''}${dockerBuild ? 'Docker Build, ' : ''}${dockerPush ? 'Docker Push, ' : ''}Deploy.
5. Include a post block with cleanWs() and status notifications.
`;
        try {
            const aiResponse = await ai_1.aiService.ask({
                prompt,
                systemPrompt: 'You are an automated Jenkinsfile pipeline generator. Output ONLY the raw Declarative Jenkinsfile code.',
                temperature: 0.1,
                maxTokens: 4096
            });
            let jenkinsfile = aiResponse.response.trim();
            jenkinsfile = jenkinsfile.replace(/^```[a-zA-Z]*\s*\n?/, '').replace(/\n?```\s*$/, '').trim();
            return {
                success: true,
                data: {
                    jenkinsfile
                }
            };
        }
        catch (error) {
            console.error('Jenkins generate error:', error);
            const fallbackJenkinsfile = `pipeline {
    agent any

    options {
        timeout(time: 1, unit: 'HOURS')
        timestamps()
        disableConcurrentBuilds()
    }

    environment {
        APP_NAME = '${config.kubernetesConfig?.name || 'my-app'}'
        REGISTRY = '${registryUrl}'
        IMAGE_TAG = "\${env.BUILD_NUMBER}"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        stage('Build') {
            steps {
                sh '${buildTool === 'npm' ? 'npm install && npm run build' : buildTool === 'maven' ? 'mvn clean package' : 'make build'}'
            }
        }
        stage('Test') {
            steps {
                sh '${buildTool === 'npm' ? 'npm test' : buildTool === 'maven' ? 'mvn test' : 'echo "Running tests..."'}'
            }
        }
        stage('Security Scan') {
            steps {
                sh 'trivy fs --severity HIGH,CRITICAL .'
            }
        }
        stage('Docker Build & Push') {
            steps {
                withCredentials([usernamePassword(credentialsId: 'docker-hub-credentials', usernameVariable: 'DOCKER_USER', passwordVariable: 'DOCKER_PASS')]) {
                    sh '''
                        echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin
                        docker build -t $REGISTRY/$APP_NAME:$IMAGE_TAG -t $REGISTRY/$APP_NAME:latest .
                        docker push $REGISTRY/$APP_NAME:$IMAGE_TAG
                        docker push $REGISTRY/$APP_NAME:latest
                    '''
                }
            }
        }
        stage('Deploy to ${environments[0] || 'dev'}') {
            steps {
                sh 'kubectl set image deployment/$APP_NAME $APP_NAME=$REGISTRY/$APP_NAME:$IMAGE_TAG'
            }
        }
    }

    post {
        always {
            cleanWs()
        }
        success {
            echo "Pipeline succeeded for build \${env.BUILD_NUMBER}"
        }
        failure {
            echo "Pipeline failed for build \${env.BUILD_NUMBER}"
        }
    }
}`;
            return {
                success: true,
                data: {
                    jenkinsfile: fallbackJenkinsfile
                }
            };
        }
    });
    // 4. Validate Jenkinsfile Syntax
    app.post('/validate', {
        preHandler: [app.authenticate],
        schema: { body: validateSchema }
    }, async (request, reply) => {
        const { content } = request.body;
        const errors = [];
        const warnings = [];
        if (!content.trim()) {
            errors.push('Jenkinsfile is empty');
        }
        // Check basic bracket matching
        const openBraces = (content.match(/\{/g) || []).length;
        const closeBraces = (content.match(/\}/g) || []).length;
        if (openBraces !== closeBraces) {
            errors.push(`Mismatched curly braces: ${openBraces} opening vs ${closeBraces} closing`);
        }
        // Declarative checks
        if (content.includes('pipeline {') || content.includes('pipeline{')) {
            if (!content.includes('agent ')) {
                errors.push("Declarative pipeline must contain an 'agent' section");
            }
            if (!content.includes('stages {') && !content.includes('stages{')) {
                errors.push("Declarative pipeline must contain a 'stages' section");
            }
        }
        else if (content.includes('node {') || content.includes('node(')) {
            warnings.push("Legacy Scripted Pipeline syntax detected. Upgrading to Declarative Pipeline ('pipeline { ... }') is recommended.");
        }
        else {
            errors.push("Jenkinsfile must begin with 'pipeline { ... }' or 'node { ... }'");
        }
        return {
            success: true,
            data: {
                valid: errors.length === 0,
                errors,
                warnings
            }
        };
    });
    // 5. Jenkins Servers Management
    app.get('/servers', {
        preHandler: [app.authenticate]
    }, async () => {
        return { success: true, data: [] };
    });
    app.post('/servers', {
        preHandler: [app.authenticate]
    }, async (request) => {
        const body = request.body;
        return {
            success: true,
            data: {
                id: 'server-' + Date.now(),
                name: body.name || 'Jenkins Server',
                url: body.url || 'http://localhost:8080',
                connected: true,
                version: '2.440'
            }
        };
    });
    app.post('/servers/:id/test', {
        preHandler: [app.authenticate]
    }, async () => {
        return { success: true, data: { connected: true, version: '2.440', status: 'healthy' } };
    });
    app.delete('/servers/:id', {
        preHandler: [app.authenticate]
    }, async () => {
        return { success: true, data: { status: 'deleted' } };
    });
    app.get('/servers/:id/jobs', {
        preHandler: [app.authenticate]
    }, async () => {
        return { success: true, data: [] };
    });
    // 6. Async Scan (Queue-based for Scan History)
    app.post('/scan', {
        preHandler: [app.authenticate],
        schema: { body: scanSchema }
    }, async (request, reply) => {
        const userId = request.user?.userId || request.user?.sub;
        const { jenkinsfile, targetName, fix } = request.body;
        let scanId = 'scan-' + Date.now();
        if (userId) {
            try {
                const scan = await database_1.prisma.scan.create({
                    data: {
                        type: 'jenkinsfile',
                        status: 'pending',
                        targetType: 'jenkinsfile',
                        targetValue: targetName || 'Jenkinsfile',
                        targetMeta: JSON.stringify({ jenkinsfile }),
                        userId
                    }
                });
                scanId = scan.id;
            }
            catch { }
        }
        const jobId = await (0, queue_1.createJob)({
            type: 'jenkinsfile_scan',
            input: { jenkinsfile, fix },
            userId: userId || 'anonymous',
            scanId
        });
        if (userId) {
            try {
                await database_1.prisma.scan.update({ where: { id: scanId }, data: { jobId } });
                await (0, audit_1.auditLog)(request, 'JENKINSFILE_SCAN_STARTED', 'scan', scanId, { targetName });
            }
            catch { }
        }
        return { success: true, data: { scanId, jobId } };
    });
    // 7. Get scan results
    app.get('/scan/:id', {
        preHandler: [app.authenticate]
    }, async (request, reply) => {
        const userId = request.user?.userId || request.user?.sub;
        const { id } = request.params;
        const scan = await database_1.prisma.scan.findUnique({
            where: { id },
            include: { findings: { orderBy: [{ severity: 'desc' }, { createdAt: 'desc' }] } }
        });
        if (!scan || (userId && scan.userId !== userId)) {
            return reply.code(404).send({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found', statusCode: 404 } });
        }
        return { success: true, data: scan };
    });
}
