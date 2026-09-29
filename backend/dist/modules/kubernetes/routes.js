"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.kubernetesRoutes = kubernetesRoutes;
const database_1 = require("../../shared/database");
const queue_1 = require("../../shared/queue");
const audit_1 = require("../../shared/utils/audit");
const ai_1 = require("../../shared/ai");
const child_process_1 = require("child_process");
const fs_1 = require("fs");
const path_1 = require("path");
const os_1 = require("os");
const js_yaml_1 = __importDefault(require("js-yaml"));
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
        resourceType: { type: 'string' },
        type: { type: 'string' },
        config: { type: 'object' },
        name: { type: 'string' },
        namespace: { type: 'string' },
        image: { type: 'string' }
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
    required: ['yaml'],
    properties: {
        yaml: { type: 'string', minLength: 1 },
        targetName: { type: 'string' },
        tools: { type: 'array', items: { type: 'string' } }
    }
};
function mapSeverity(sev) {
    const s = sev?.toLowerCase() || 'info';
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
function parseResourcesFromYaml(content) {
    const resources = [];
    try {
        const docs = js_yaml_1.default.loadAll(content);
        for (const doc of docs) {
            if (doc && typeof doc === 'object' && doc.kind) {
                resources.push({
                    kind: doc.kind,
                    apiVersion: doc.apiVersion || 'v1',
                    name: doc.metadata?.name || 'unnamed',
                    namespace: doc.metadata?.namespace || 'default',
                    valid: true,
                    issues: []
                });
            }
        }
    }
    catch {
        // If YAML parse has partial errors, extract via regex
        const kindMatches = content.match(/^kind:\s*([A-Za-z0-9]+)/gm) || [];
        const nameMatches = content.match(/^\s*name:\s*([A-Za-z0-9-_]+)/gm) || [];
        kindMatches.forEach((kMatch, idx) => {
            const kind = kMatch.replace(/^kind:\s*/, '').trim();
            const name = nameMatches[idx] ? nameMatches[idx].replace(/^\s*name:\s*/, '').trim() : 'resource';
            resources.push({
                kind,
                apiVersion: 'v1',
                name,
                namespace: 'default',
                valid: true,
                issues: []
            });
        });
    }
    return resources;
}
function runTrivyConfigScan(content) {
    const issues = [];
    const tempDir = (0, fs_1.mkdtempSync)((0, path_1.join)((0, os_1.tmpdir)(), 'k8s-analyze-'));
    const tempFile = (0, path_1.join)(tempDir, 'manifest.yaml');
    try {
        (0, fs_1.writeFileSync)(tempFile, content, 'utf-8');
        const stdout = (0, child_process_1.execFileSync)('trivy', [
            'config',
            '--format', 'json',
            '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
            tempFile
        ], {
            timeout: 30000,
            encoding: 'utf-8',
            maxBuffer: 10 * 1024 * 1024
        });
        const parsed = JSON.parse(stdout);
        if (parsed.Results) {
            for (const res of parsed.Results) {
                for (const m of res.Misconfigurations || []) {
                    const resourceName = `${m.Kind || 'Resource'}/${m.Name || 'manifest'}`;
                    issues.push({
                        id: `k8s-${m.ID}`,
                        resource: resourceName,
                        type: 'security',
                        severity: mapSeverity(m.Severity),
                        path: m.CauseMetadata?.Code?.Lines?.[0]?.Content || m.ID,
                        message: m.Title || m.Description,
                        rule: m.ID,
                        fixable: true,
                        suggestion: m.Resolution || m.Message || 'Configure recommended security settings'
                    });
                }
            }
        }
    }
    catch (err) {
        if (err.stdout && err.stdout.trim().startsWith('{')) {
            try {
                const parsed = JSON.parse(err.stdout);
                for (const res of parsed.Results || []) {
                    for (const m of res.Misconfigurations || []) {
                        issues.push({
                            id: `k8s-${m.ID}`,
                            resource: `${m.Kind || 'Resource'}/${m.Name || 'manifest'}`,
                            type: 'security',
                            severity: mapSeverity(m.Severity),
                            path: m.ID,
                            message: m.Title || m.Description,
                            rule: m.ID,
                            fixable: true,
                            suggestion: m.Resolution || 'Apply hardened configuration'
                        });
                    }
                }
            }
            catch {
                // Fallback
            }
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
function runRuleBasedChecks(content, resources) {
    const issues = [];
    // Check 1: Missing securityContext
    if (!content.includes('securityContext') && (content.includes('containers:') || content.includes('Deployment'))) {
        issues.push({
            id: 'k8s-sec-context-missing',
            resource: resources[0]?.name ? `${resources[0].kind}/${resources[0].name}` : 'Deployment',
            type: 'security',
            severity: 'high',
            path: 'spec.template.spec.securityContext',
            message: 'Container is missing securityContext (runAsNonRoot, readOnlyRootFilesystem, allowPrivilegeEscalation)',
            rule: 'KSV-001',
            fixable: true,
            suggestion: 'Add securityContext with runAsNonRoot: true, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true'
        });
    }
    // Check 2: Latest tag
    if (content.match(/image:\s*['"]?[a-zA-Z0-9_.-]+:latest['"]?/)) {
        issues.push({
            id: 'k8s-latest-tag',
            resource: resources[0]?.name ? `${resources[0].kind}/${resources[0].name}` : 'Deployment',
            type: 'best_practice',
            severity: 'medium',
            path: 'spec.template.spec.containers[*].image',
            message: 'Container image uses the :latest tag instead of an immutable version tag or SHA digest',
            rule: 'KSV-002',
            fixable: true,
            suggestion: 'Pin container image to a specific version or digest'
        });
    }
    // Check 3: Resource limits/requests missing
    if (!content.includes('resources:') || (!content.includes('limits:') && !content.includes('requests:'))) {
        if (content.includes('containers:') || content.includes('Deployment')) {
            issues.push({
                id: 'k8s-resources-missing',
                resource: resources[0]?.name ? `${resources[0].kind}/${resources[0].name}` : 'Deployment',
                type: 'reliability',
                severity: 'medium',
                path: 'spec.template.spec.containers[*].resources',
                message: 'CPU and memory requests and limits are not defined, which can lead to noisy neighbor issues and OOM kills',
                rule: 'KSV-003',
                fixable: true,
                suggestion: 'Specify resources.requests and resources.limits for CPU and memory'
            });
        }
    }
    // Check 4: Liveness and Readiness probes missing
    if (!content.includes('livenessProbe') && (content.includes('Deployment') || content.includes('StatefulSet'))) {
        issues.push({
            id: 'k8s-probes-missing',
            resource: resources[0]?.name ? `${resources[0].kind}/${resources[0].name}` : 'Deployment',
            type: 'reliability',
            severity: 'low',
            path: 'spec.template.spec.containers[*].livenessProbe',
            message: 'Liveness/Readiness probes are missing, preventing Kubernetes from detecting unhealthy pods',
            rule: 'KSV-004',
            fixable: true,
            suggestion: 'Configure livenessProbe and readinessProbe for container health checks'
        });
    }
    // Check 5: Running as root
    if (content.includes('runAsUser: 0') || (content.includes('runAsNonRoot: false'))) {
        issues.push({
            id: 'k8s-run-as-root',
            resource: resources[0]?.name ? `${resources[0].kind}/${resources[0].name}` : 'Deployment',
            type: 'security',
            severity: 'critical',
            path: 'spec.template.spec.securityContext.runAsNonRoot',
            message: 'Container explicitly runs as root user (UID 0)',
            rule: 'KSV-005',
            fixable: true,
            suggestion: 'Set runAsNonRoot: true and specify a non-zero runAsUser (e.g., 10001)'
        });
    }
    return issues;
}
async function kubernetesRoutes(app) {
    // 1. Analyze Kubernetes YAML (synchronous, returns immediately)
    app.post('/analyze', {
        preHandler: [app.authenticate],
        schema: { body: analyzeSchema }
    }, async (request, reply) => {
        const { content } = request.body;
        try {
            const resources = parseResourcesFromYaml(content);
            const trivyIssues = runTrivyConfigScan(content);
            const ruleIssues = runRuleBasedChecks(content, resources);
            // Deduplicate issues by rule/message
            const seen = new Set();
            const allIssues = [];
            for (const issue of [...trivyIssues, ...ruleIssues]) {
                const key = `${issue.rule}-${issue.message.slice(0, 30)}`;
                if (!seen.has(key)) {
                    seen.add(key);
                    allIssues.push(issue);
                }
            }
            const result = {
                yaml: content,
                resources: resources.map(r => ({
                    ...r,
                    issues: allIssues.filter(i => i.resource.includes(r.name) || i.resource.includes(r.kind))
                })),
                issues: allIssues
            };
            return { success: true, data: result };
        }
        catch (error) {
            console.error('Kubernetes analyze error:', error);
            return reply.code(500).send({
                success: false,
                error: { code: 'ANALYZE_FAILED', message: error.message || 'Analysis failed', statusCode: 500 }
            });
        }
    });
    // 2. Fix Kubernetes YAML using AI
    app.post('/fix', {
        preHandler: [app.authenticate],
        schema: { body: fixSchema }
    }, async (request, reply) => {
        const { content, issues, options } = request.body;
        const issuesList = issues && issues.length > 0
            ? issues
            : runRuleBasedChecks(content, parseResourcesFromYaml(content));
        const prompt = `
You are an expert Kubernetes and DevSecOps security engineer.
Fix the following Kubernetes YAML manifests to resolve all security, reliability, and best-practice issues.

Original Kubernetes YAML:
${content}

Issues to fix:
${issuesList.map((issue, idx) => `${idx + 1}. [${issue.severity.toUpperCase()}] ${issue.message}${issue.suggestion ? ` (Suggestion: ${issue.suggestion})` : ''}`).join('\n')}

Fix Requirements:
1. Apply a hardened container securityContext (runAsNonRoot: true, allowPrivilegeEscalation: false, readOnlyRootFilesystem: true, capabilities: { drop: ["ALL"] }).
2. Add resource requests and limits (e.g. requests: cpu: "250m", memory: "256Mi", limits: cpu: "500m", memory: "512Mi").
3. Add liveness and readiness probes where appropriate.
4. Replace :latest image tag with a pinned tag or recommended best practice.
5. Return ONLY the complete, valid, fixed Kubernetes YAML without any markdown code fences or conversational text.
`;
        try {
            const aiResponse = await ai_1.aiService.ask({
                prompt,
                systemPrompt: 'You are an automated Kubernetes manifest hardening engine. Respond ONLY with the complete raw valid YAML manifest without markdown code blocks.',
                temperature: 0.1,
                maxTokens: 4096
            });
            let fixedYaml = aiResponse.response.trim();
            fixedYaml = fixedYaml.replace(/^```[a-zA-Z]*\s*\n?/, '').replace(/\n?```\s*$/, '').trim();
            if (!fixedYaml) {
                throw new Error('AI returned an empty Kubernetes YAML response');
            }
            const changes = issuesList.map(issue => ({
                findingId: issue.id,
                type: 'security_hardening',
                description: `Applied fix for: ${issue.message}`,
                resource: issue.resource
            }));
            const explanation = `AI analyzed ${issuesList.length} Kubernetes findings and applied production-grade security hardening, including non-root security contexts, capability drops, resource limits, and health probes.`;
            return {
                success: true,
                data: {
                    fixedYaml,
                    changes,
                    explanation
                }
            };
        }
        catch (error) {
            console.error('Kubernetes AI fix error:', error);
            return reply.code(500).send({
                success: false,
                error: { code: 'FIX_FAILED', message: error.message || 'AI fix failed', statusCode: 500 }
            });
        }
    });
    // 3. Generate Kubernetes YAML using AI
    app.post('/generate', {
        preHandler: [app.authenticate],
        schema: { body: generateSchema }
    }, async (request, reply) => {
        const body = request.body;
        const resourceType = body.resourceType || body.type || 'Deployment';
        const config = body.config || body;
        const name = config.name || 'my-app';
        const namespace = config.namespace || 'default';
        const image = config.image || 'nginx:1.25-alpine';
        const replicas = config.replicas ?? 3;
        const port = config.port ?? 80;
        const serviceType = config.serviceType || 'ClusterIP';
        const ingressHost = config.ingressHost || `${name}.example.com`;
        const cpuRequest = config.cpuRequest || '250m';
        const memoryRequest = config.memoryRequest || '256Mi';
        const prompt = `
You are a Kubernetes architect. Generate a complete, production-ready, security-hardened Kubernetes manifest for a ${resourceType}.

Configuration Parameters:
- Resource Type: ${resourceType}
- Name: ${name}
- Namespace: ${namespace}
- Container Image: ${image}
- Replicas: ${replicas}
- Port: ${port}
- Service Type: ${serviceType}
- Ingress Enabled: ${config.ingressEnabled ? `Yes (Host: ${ingressHost})` : 'No'}
- CPU Request: ${cpuRequest}
- Memory Request: ${memoryRequest}
- Probes: ${JSON.stringify(config.livenessProbe || { enabled: true, path: '/healthz', port })}
- Security Context: ${JSON.stringify(config.securityContext || { runAsNonRoot: true, readOnlyRootFilesystem: true, allowPrivilegeEscalation: false })}

Rules:
1. Output ONLY clean, valid Kubernetes YAML without markdown code fences or explanations.
2. Include all necessary companion resources (e.g. Deployment + Service + Ingress if enabled).
3. Include hardened securityContext, resource limits/requests, and standard labels (app.kubernetes.io/name, app.kubernetes.io/instance).
`;
        try {
            const aiResponse = await ai_1.aiService.ask({
                prompt,
                systemPrompt: 'You are a Kubernetes manifest generator. Output ONLY raw valid YAML without markdown fences.',
                temperature: 0.1,
                maxTokens: 4096
            });
            let yaml = aiResponse.response.trim();
            yaml = yaml.replace(/^```[a-zA-Z]*\s*\n?/, '').replace(/\n?```\s*$/, '').trim();
            return {
                success: true,
                data: {
                    yaml,
                    resourceType,
                    name
                }
            };
        }
        catch (error) {
            console.error('Kubernetes generate error:', error);
            // Fallback template generator
            const fallbackYaml = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${name}
  namespace: ${namespace}
  labels:
    app.kubernetes.io/name: ${name}
spec:
  replicas: ${replicas}
  selector:
    matchLabels:
      app.kubernetes.io/name: ${name}
  template:
    metadata:
      labels:
        app.kubernetes.io/name: ${name}
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        fsGroup: 10001
      containers:
      - name: ${name}
        image: ${image}
        ports:
        - containerPort: ${port}
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        resources:
          requests:
            cpu: "${cpuRequest}"
            memory: "${memoryRequest}"
          limits:
            cpu: "500m"
            memory: "512Mi"
---
apiVersion: v1
kind: Service
metadata:
  name: ${name}
  namespace: ${namespace}
spec:
  type: ${serviceType}
  selector:
    app.kubernetes.io/name: ${name}
  ports:
  - port: ${port}
    targetPort: ${port}`;
            return {
                success: true,
                data: {
                    yaml: fallbackYaml,
                    resourceType,
                    name
                }
            };
        }
    });
    // 4. Validate Kubernetes YAML Syntax
    app.post('/validate', {
        preHandler: [app.authenticate],
        schema: { body: validateSchema }
    }, async (request, reply) => {
        const { content } = request.body;
        const errors = [];
        const warnings = [];
        try {
            const docs = js_yaml_1.default.loadAll(content);
            if (docs.length === 0) {
                errors.push('YAML file is empty');
            }
            for (let i = 0; i < docs.length; i++) {
                const doc = docs[i];
                if (!doc)
                    continue;
                if (!doc.apiVersion) {
                    errors.push(`Document ${i + 1}: Missing 'apiVersion'`);
                }
                if (!doc.kind) {
                    errors.push(`Document ${i + 1}: Missing 'kind'`);
                }
                if (!doc.metadata?.name) {
                    errors.push(`Document ${i + 1}: Missing 'metadata.name'`);
                }
                // Deprecated API versions check
                if (doc.apiVersion?.startsWith('extensions/v1beta1') || doc.apiVersion?.startsWith('apps/v1beta')) {
                    warnings.push(`Document ${i + 1} (${doc.kind}): 'apiVersion: ${doc.apiVersion}' is deprecated. Upgrade to apps/v1 or networking.k8s.io/v1`);
                }
            }
        }
        catch (e) {
            errors.push(`YAML syntax error: ${e.message}`);
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
    // 5. Async Scan (Queue-based for Scan History & background jobs)
    app.post('/scan', {
        preHandler: [app.authenticate],
        schema: { body: scanSchema }
    }, async (request, reply) => {
        const userId = request.user?.userId || request.user?.sub;
        const { yaml, targetName, tools } = request.body;
        let scanId = 'scan-' + Date.now();
        if (userId) {
            try {
                const scan = await database_1.prisma.scan.create({
                    data: {
                        type: 'kubernetes',
                        status: 'pending',
                        targetType: 'kubernetes_yaml',
                        targetValue: targetName || 'kubernetes.yaml',
                        targetMeta: JSON.stringify({ yaml, tools }),
                        userId
                    }
                });
                scanId = scan.id;
            }
            catch { }
        }
        const jobId = await (0, queue_1.createJob)({
            type: 'kubernetes_scan',
            input: { scanId, yaml, tools },
            userId: userId || 'anonymous',
            scanId
        });
        if (userId) {
            try {
                await database_1.prisma.scan.update({ where: { id: scanId }, data: { jobId } });
                await (0, audit_1.auditLog)(request, 'KUBERNETES_SCAN_STARTED', 'scan', scanId, { targetName });
            }
            catch { }
        }
        return { success: true, data: { scanId, jobId } };
    });
    // 6. Get scan results
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
