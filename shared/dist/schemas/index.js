"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.updateSettingsSchema = exports.createJobSchema = exports.dependencyFixSchema = exports.dependencyScanSchema = exports.logInvestigateSchema = exports.githubScanSchema = exports.githubConnectSchema = exports.jenkinsfileGenerateSchema = exports.jenkinsfileAnalyzeSchema = exports.kubernetesGenerateSchema = exports.kubernetesAnalyzeSchema = exports.dockerImageFixSchema = exports.dockerImageScanSchema = exports.dockerfileFixSchema = exports.dockerfileAnalyzeSchema = exports.changePasswordSchema = exports.registerSchema = exports.loginSchema = void 0;
const zod_1 = require("zod");
// ============================================
// Auth Schemas
// ============================================
exports.loginSchema = zod_1.z.object({
    email: zod_1.z.string().email('Invalid email address'),
    password: zod_1.z.string().min(8, 'Password must be at least 8 characters'),
    rememberMe: zod_1.z.boolean().optional()
});
exports.registerSchema = zod_1.z.object({
    email: zod_1.z.string().email('Invalid email address'),
    password: zod_1.z.string()
        .min(8, 'Password must be at least 8 characters')
        .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
        .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
        .regex(/[0-9]/, 'Password must contain at least one number')
        .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
    name: zod_1.z.string().min(2, 'Name must be at least 2 characters').max(100)
});
exports.changePasswordSchema = zod_1.z.object({
    currentPassword: zod_1.z.string().min(1),
    newPassword: zod_1.z.string().min(8)
});
// ============================================
// Dockerfile Schemas
// ============================================
exports.dockerfileAnalyzeSchema = zod_1.z.object({
    content: zod_1.z.string().min(1, 'Dockerfile content required').max(100000)
});
exports.dockerfileFixSchema = zod_1.z.object({
    content: zod_1.z.string().min(1),
    issues: zod_1.z.array(zod_1.z.object({
        id: zod_1.z.string(),
        type: zod_1.z.enum(['syntax', 'security', 'best_practice', 'performance', 'style']),
        severity: zod_1.z.enum(['critical', 'high', 'medium', 'low', 'info']),
        line: zod_1.z.number(),
        message: zod_1.z.string(),
        rule: zod_1.z.string(),
        fixable: zod_1.z.boolean(),
        suggestion: zod_1.z.string().optional()
    })).optional(),
    options: zod_1.z.object({
        fixSecurity: zod_1.z.boolean().optional(),
        fixBestPractices: zod_1.z.boolean().optional(),
        fixPerformance: zod_1.z.boolean().optional(),
        preserveComments: zod_1.z.boolean().optional(),
        baseImagePolicy: zod_1.z.enum(['latest', 'pinned', 'distroless', 'alpine']).optional()
    }).optional()
});
// ============================================
// Docker Image Schemas
// ============================================
exports.dockerImageScanSchema = zod_1.z.object({
    image: zod_1.z.string().regex(/^[a-z0-9]+([._-][a-z0-9]+)*(\/[a-z0-9]+([._-][a-z0-9]+)*)*(:[\w][\w.-]{0,127})?(@sha256:[a-f0-9]{64})?$/, 'Invalid Docker image reference')
});
exports.dockerImageFixSchema = zod_1.z.object({
    image: zod_1.z.string(),
    vulnerabilities: zod_1.z.array(zod_1.z.object({
        id: zod_1.z.string(),
        package: zod_1.z.string(),
        installedVersion: zod_1.z.string(),
        fixedVersion: zod_1.z.string().optional(),
        severity: zod_1.z.enum(['critical', 'high', 'medium', 'low', 'info']),
        fixAvailable: zod_1.z.boolean()
    })),
    dockerfile: zod_1.z.string().optional(),
    options: zod_1.z.object({
        strategy: zod_1.z.enum(['update_packages', 'change_base_image', 'minimal']),
        allowBreakingChanges: zod_1.z.boolean().optional(),
        targetBaseImage: zod_1.z.string().optional()
    }).optional()
});
// ============================================
// Kubernetes Schemas
// ============================================
exports.kubernetesAnalyzeSchema = zod_1.z.object({
    content: zod_1.z.string().min(1)
});
exports.kubernetesGenerateSchema = zod_1.z.object({
    resourceType: zod_1.z.enum(['Deployment', 'Service', 'Ingress', 'ConfigMap', 'Secret', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'Namespace', 'ServiceAccount', 'Role', 'RoleBinding', 'NetworkPolicy', 'PersistentVolumeClaim']),
    config: zod_1.z.record(zod_1.z.unknown())
});
// ============================================
// Jenkins Schemas
// ============================================
exports.jenkinsfileAnalyzeSchema = zod_1.z.object({
    content: zod_1.z.string().min(1)
});
exports.jenkinsfileGenerateSchema = zod_1.z.object({
    config: zod_1.z.object({
        application: zod_1.z.enum(['nodejs', 'python', 'java', 'go', 'docker', 'generic']),
        repositoryUrl: zod_1.z.string().url(),
        buildTool: zod_1.z.enum(['npm', 'maven', 'gradle', 'pip', 'make', 'none']),
        testing: zod_1.z.boolean(),
        dockerBuild: zod_1.z.boolean(),
        securityScan: zod_1.z.boolean(),
        dockerPush: zod_1.z.boolean(),
        deployment: zod_1.z.enum(['kubernetes', 'vm', 'none', 'ecs', 'cloudrun']),
        environments: zod_1.z.array(zod_1.z.enum(['dev', 'staging', 'production'])),
        kubernetesConfig: zod_1.z.record(zod_1.z.unknown()).optional()
    })
});
// ============================================
// GitHub Schemas
// ============================================
exports.githubConnectSchema = zod_1.z.object({
    token: zod_1.z.string().min(1),
    url: zod_1.z.string().url().optional()
});
exports.githubScanSchema = zod_1.z.object({
    repoUrl: zod_1.z.string().url(),
    branch: zod_1.z.string().default('main'),
    scanTypes: zod_1.z.array(zod_1.z.enum(['vulnerabilities', 'secrets', 'dependencies', 'code'])).default(['vulnerabilities', 'secrets', 'dependencies', 'code'])
});
// ============================================
// Logs Schemas
// ============================================
exports.logInvestigateSchema = zod_1.z.object({
    question: zod_1.z.string().min(5),
    logFileIds: zod_1.z.array(zod_1.z.string()).min(1),
    timeRange: zod_1.z.object({
        start: zod_1.z.string(),
        end: zod_1.z.string()
    }).optional()
});
// ============================================
// Dependency Schemas
// ============================================
exports.dependencyScanSchema = zod_1.z.object({
    repoUrl: zod_1.z.string().url(),
    branch: zod_1.z.string().default('main')
});
exports.dependencyFixSchema = zod_1.z.object({
    package: zod_1.z.string(),
    currentVersion: zod_1.z.string(),
    targetVersion: zod_1.z.string(),
    manifestPath: zod_1.z.string(),
    vulnerabilityIds: zod_1.z.array(zod_1.z.string()).optional()
});
// ============================================
// Job Schemas
// ============================================
exports.createJobSchema = zod_1.z.object({
    type: zod_1.z.enum([
        'dockerfile_scan', 'dockerfile_fix', 'docker_image_scan', 'docker_image_fix',
        'kubernetes_scan', 'kubernetes_fix', 'kubernetes_generate',
        'jenkinsfile_scan', 'jenkinsfile_fix', 'jenkinsfile_generate',
        'github_repo_scan', 'github_dependency_scan', 'github_secret_scan', 'github_code_scan',
        'log_investigation', 'dependency_scan', 'dependency_fix', 'sbom_generation'
    ]),
    input: zod_1.z.record(zod_1.z.unknown()),
    priority: zod_1.z.enum(['low', 'normal', 'high']).default('normal')
});
// ============================================
// Settings Schemas
// ============================================
exports.updateSettingsSchema = zod_1.z.object({
    ai: zod_1.z.object({
        provider: zod_1.z.enum(['apps_script', 'openai', 'gemini', 'anthropic', 'custom']),
        appsScriptUrl: zod_1.z.string().url().optional().or(zod_1.z.literal('')),
        defaultModel: zod_1.z.string().optional(),
        temperature: zod_1.z.number().min(0).max(2).optional(),
        maxTokens: zod_1.z.number().min(1).max(100000).optional()
    }).optional(),
    scanning: zod_1.z.object({
        maxConcurrentScans: zod_1.z.number().min(1).max(20).optional(),
        scanTimeout: zod_1.z.number().min(10000).max(600000).optional(),
        defaultTools: zod_1.z.array(zod_1.z.string()).optional()
    }).optional(),
    notifications: zod_1.z.object({
        emailEnabled: zod_1.z.boolean().optional(),
        fromEmail: zod_1.z.string().email().optional().or(zod_1.z.literal(''))
    }).optional()
});
