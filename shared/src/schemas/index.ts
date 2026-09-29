import { z } from 'zod';

// ============================================
// Auth Schemas
// ============================================

export const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters'),
  rememberMe: z.boolean().optional()
});

export const registerSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string()
    .min(8, 'Password must be at least 8 characters')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number')
    .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character'),
  name: z.string().min(2, 'Name must be at least 2 characters').max(100)
});

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1),
  newPassword: z.string().min(8)
});

// ============================================
// Dockerfile Schemas
// ============================================

export const dockerfileAnalyzeSchema = z.object({
  content: z.string().min(1, 'Dockerfile content required').max(100000)
});

export const dockerfileFixSchema = z.object({
  content: z.string().min(1),
  issues: z.array(z.object({
    id: z.string(),
    type: z.enum(['syntax', 'security', 'best_practice', 'performance', 'style']),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
    line: z.number(),
    message: z.string(),
    rule: z.string(),
    fixable: z.boolean(),
    suggestion: z.string().optional()
  })).optional(),
  options: z.object({
    fixSecurity: z.boolean().optional(),
    fixBestPractices: z.boolean().optional(),
    fixPerformance: z.boolean().optional(),
    preserveComments: z.boolean().optional(),
    baseImagePolicy: z.enum(['latest', 'pinned', 'distroless', 'alpine']).optional()
  }).optional()
});

// ============================================
// Docker Image Schemas
// ============================================

export const dockerImageScanSchema = z.object({
  image: z.string().regex(/^[a-z0-9]+([._-][a-z0-9]+)*(\/[a-z0-9]+([._-][a-z0-9]+)*)*(:[\w][\w.-]{0,127})?(@sha256:[a-f0-9]{64})?$/, 'Invalid Docker image reference')
});

export const dockerImageFixSchema = z.object({
  image: z.string(),
  vulnerabilities: z.array(z.object({
    id: z.string(),
    package: z.string(),
    installedVersion: z.string(),
    fixedVersion: z.string().optional(),
    severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
    fixAvailable: z.boolean()
  })),
  dockerfile: z.string().optional(),
  options: z.object({
    strategy: z.enum(['update_packages', 'change_base_image', 'minimal']),
    allowBreakingChanges: z.boolean().optional(),
    targetBaseImage: z.string().optional()
  }).optional()
});

// ============================================
// Kubernetes Schemas
// ============================================

export const kubernetesAnalyzeSchema = z.object({
  content: z.string().min(1)
});

export const kubernetesGenerateSchema = z.object({
  resourceType: z.enum(['Deployment', 'Service', 'Ingress', 'ConfigMap', 'Secret', 'StatefulSet', 'DaemonSet', 'Job', 'CronJob', 'Namespace', 'ServiceAccount', 'Role', 'RoleBinding', 'NetworkPolicy', 'PersistentVolumeClaim']),
  config: z.record(z.unknown())
});

// ============================================
// Jenkins Schemas
// ============================================

export const jenkinsfileAnalyzeSchema = z.object({
  content: z.string().min(1)
});

export const jenkinsfileGenerateSchema = z.object({
  config: z.object({
    application: z.enum(['nodejs', 'python', 'java', 'go', 'docker', 'generic']),
    repositoryUrl: z.string().url(),
    buildTool: z.enum(['npm', 'maven', 'gradle', 'pip', 'make', 'none']),
    testing: z.boolean(),
    dockerBuild: z.boolean(),
    securityScan: z.boolean(),
    dockerPush: z.boolean(),
    deployment: z.enum(['kubernetes', 'vm', 'none', 'ecs', 'cloudrun']),
    environments: z.array(z.enum(['dev', 'staging', 'production'])),
    kubernetesConfig: z.record(z.unknown()).optional()
  })
});

// ============================================
// GitHub Schemas
// ============================================

export const githubConnectSchema = z.object({
  token: z.string().min(1),
  url: z.string().url().optional()
});

export const githubScanSchema = z.object({
  repoUrl: z.string().url(),
  branch: z.string().default('main'),
  scanTypes: z.array(z.enum(['vulnerabilities', 'secrets', 'dependencies', 'code'])).default(['vulnerabilities', 'secrets', 'dependencies', 'code'])
});

// ============================================
// Logs Schemas
// ============================================

export const logInvestigateSchema = z.object({
  question: z.string().min(5),
  logFileIds: z.array(z.string()).min(1),
  timeRange: z.object({
    start: z.string(),
    end: z.string()
  }).optional()
});

// ============================================
// Dependency Schemas
// ============================================

export const dependencyScanSchema = z.object({
  repoUrl: z.string().url(),
  branch: z.string().default('main')
});

export const dependencyFixSchema = z.object({
  package: z.string(),
  currentVersion: z.string(),
  targetVersion: z.string(),
  manifestPath: z.string(),
  vulnerabilityIds: z.array(z.string()).optional()
});

// ============================================
// Job Schemas
// ============================================

export const createJobSchema = z.object({
  type: z.enum([
    'dockerfile_scan', 'dockerfile_fix', 'docker_image_scan', 'docker_image_fix',
    'kubernetes_scan', 'kubernetes_fix', 'kubernetes_generate',
    'jenkinsfile_scan', 'jenkinsfile_fix', 'jenkinsfile_generate',
    'github_repo_scan', 'github_dependency_scan', 'github_secret_scan', 'github_code_scan',
    'log_investigation', 'dependency_scan', 'dependency_fix', 'sbom_generation'
  ]),
  input: z.record(z.unknown()),
  priority: z.enum(['low', 'normal', 'high']).default('normal')
});

// ============================================
// Settings Schemas
// ============================================

export const updateSettingsSchema = z.object({
  ai: z.object({
    provider: z.enum(['apps_script', 'openai', 'gemini', 'anthropic', 'custom']),
    appsScriptUrl: z.string().url().optional().or(z.literal('')),
    defaultModel: z.string().optional(),
    temperature: z.number().min(0).max(2).optional(),
    maxTokens: z.number().min(1).max(100000).optional()
  }).optional(),
  scanning: z.object({
    maxConcurrentScans: z.number().min(1).max(20).optional(),
    scanTimeout: z.number().min(10000).max(600000).optional(),
    defaultTools: z.array(z.string()).optional()
  }).optional(),
  notifications: z.object({
    emailEnabled: z.boolean().optional(),
    fromEmail: z.string().email().optional().or(z.literal(''))
  }).optional()
});

export type LoginInput = z.infer<typeof loginSchema>;
export type RegisterInput = z.infer<typeof registerSchema>;
export type DockerfileAnalyzeInput = z.infer<typeof dockerfileAnalyzeSchema>;
export type DockerfileFixInput = z.infer<typeof dockerfileFixSchema>;
export type DockerImageScanInput = z.infer<typeof dockerImageScanSchema>;
export type KubernetesAnalyzeInput = z.infer<typeof kubernetesAnalyzeSchema>;
export type KubernetesGenerateInput = z.infer<typeof kubernetesGenerateSchema>;
export type JenkinsfileAnalyzeInput = z.infer<typeof jenkinsfileAnalyzeSchema>;
export type JenkinsfileGenerateInput = z.infer<typeof jenkinsfileGenerateSchema>;
export type LogInvestigateInput = z.infer<typeof logInvestigateSchema>;
export type DependencyScanInput = z.infer<typeof dependencyScanSchema>;
export type DependencyFixInput = z.infer<typeof dependencyFixSchema>;