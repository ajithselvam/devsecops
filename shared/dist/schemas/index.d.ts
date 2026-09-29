import { z } from 'zod';
export declare const loginSchema: z.ZodObject<{
    email: z.ZodString;
    password: z.ZodString;
    rememberMe: z.ZodOptional<z.ZodBoolean>;
}, "strip", z.ZodTypeAny, {
    email: string;
    password: string;
    rememberMe?: boolean | undefined;
}, {
    email: string;
    password: string;
    rememberMe?: boolean | undefined;
}>;
export declare const registerSchema: z.ZodObject<{
    email: z.ZodString;
    password: z.ZodString;
    name: z.ZodString;
}, "strip", z.ZodTypeAny, {
    email: string;
    password: string;
    name: string;
}, {
    email: string;
    password: string;
    name: string;
}>;
export declare const changePasswordSchema: z.ZodObject<{
    currentPassword: z.ZodString;
    newPassword: z.ZodString;
}, "strip", z.ZodTypeAny, {
    currentPassword: string;
    newPassword: string;
}, {
    currentPassword: string;
    newPassword: string;
}>;
export declare const dockerfileAnalyzeSchema: z.ZodObject<{
    content: z.ZodString;
}, "strip", z.ZodTypeAny, {
    content: string;
}, {
    content: string;
}>;
export declare const dockerfileFixSchema: z.ZodObject<{
    content: z.ZodString;
    issues: z.ZodOptional<z.ZodArray<z.ZodObject<{
        id: z.ZodString;
        type: z.ZodEnum<["syntax", "security", "best_practice", "performance", "style"]>;
        severity: z.ZodEnum<["critical", "high", "medium", "low", "info"]>;
        line: z.ZodNumber;
        message: z.ZodString;
        rule: z.ZodString;
        fixable: z.ZodBoolean;
        suggestion: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        message: string;
        type: "performance" | "syntax" | "security" | "best_practice" | "style";
        id: string;
        severity: "critical" | "high" | "medium" | "low" | "info";
        line: number;
        rule: string;
        fixable: boolean;
        suggestion?: string | undefined;
    }, {
        message: string;
        type: "performance" | "syntax" | "security" | "best_practice" | "style";
        id: string;
        severity: "critical" | "high" | "medium" | "low" | "info";
        line: number;
        rule: string;
        fixable: boolean;
        suggestion?: string | undefined;
    }>, "many">>;
    options: z.ZodOptional<z.ZodObject<{
        fixSecurity: z.ZodOptional<z.ZodBoolean>;
        fixBestPractices: z.ZodOptional<z.ZodBoolean>;
        fixPerformance: z.ZodOptional<z.ZodBoolean>;
        preserveComments: z.ZodOptional<z.ZodBoolean>;
        baseImagePolicy: z.ZodOptional<z.ZodEnum<["latest", "pinned", "distroless", "alpine"]>>;
    }, "strip", z.ZodTypeAny, {
        fixSecurity?: boolean | undefined;
        fixBestPractices?: boolean | undefined;
        fixPerformance?: boolean | undefined;
        preserveComments?: boolean | undefined;
        baseImagePolicy?: "latest" | "pinned" | "distroless" | "alpine" | undefined;
    }, {
        fixSecurity?: boolean | undefined;
        fixBestPractices?: boolean | undefined;
        fixPerformance?: boolean | undefined;
        preserveComments?: boolean | undefined;
        baseImagePolicy?: "latest" | "pinned" | "distroless" | "alpine" | undefined;
    }>>;
}, "strip", z.ZodTypeAny, {
    content: string;
    issues?: {
        message: string;
        type: "performance" | "syntax" | "security" | "best_practice" | "style";
        id: string;
        severity: "critical" | "high" | "medium" | "low" | "info";
        line: number;
        rule: string;
        fixable: boolean;
        suggestion?: string | undefined;
    }[] | undefined;
    options?: {
        fixSecurity?: boolean | undefined;
        fixBestPractices?: boolean | undefined;
        fixPerformance?: boolean | undefined;
        preserveComments?: boolean | undefined;
        baseImagePolicy?: "latest" | "pinned" | "distroless" | "alpine" | undefined;
    } | undefined;
}, {
    content: string;
    issues?: {
        message: string;
        type: "performance" | "syntax" | "security" | "best_practice" | "style";
        id: string;
        severity: "critical" | "high" | "medium" | "low" | "info";
        line: number;
        rule: string;
        fixable: boolean;
        suggestion?: string | undefined;
    }[] | undefined;
    options?: {
        fixSecurity?: boolean | undefined;
        fixBestPractices?: boolean | undefined;
        fixPerformance?: boolean | undefined;
        preserveComments?: boolean | undefined;
        baseImagePolicy?: "latest" | "pinned" | "distroless" | "alpine" | undefined;
    } | undefined;
}>;
export declare const dockerImageScanSchema: z.ZodObject<{
    image: z.ZodString;
}, "strip", z.ZodTypeAny, {
    image: string;
}, {
    image: string;
}>;
export declare const dockerImageFixSchema: z.ZodObject<{
    image: z.ZodString;
    vulnerabilities: z.ZodArray<z.ZodObject<{
        id: z.ZodString;
        package: z.ZodString;
        installedVersion: z.ZodString;
        fixedVersion: z.ZodOptional<z.ZodString>;
        severity: z.ZodEnum<["critical", "high", "medium", "low", "info"]>;
        fixAvailable: z.ZodBoolean;
    }, "strip", z.ZodTypeAny, {
        id: string;
        severity: "critical" | "high" | "medium" | "low" | "info";
        package: string;
        installedVersion: string;
        fixAvailable: boolean;
        fixedVersion?: string | undefined;
    }, {
        id: string;
        severity: "critical" | "high" | "medium" | "low" | "info";
        package: string;
        installedVersion: string;
        fixAvailable: boolean;
        fixedVersion?: string | undefined;
    }>, "many">;
    dockerfile: z.ZodOptional<z.ZodString>;
    options: z.ZodOptional<z.ZodObject<{
        strategy: z.ZodEnum<["update_packages", "change_base_image", "minimal"]>;
        allowBreakingChanges: z.ZodOptional<z.ZodBoolean>;
        targetBaseImage: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        strategy: "update_packages" | "change_base_image" | "minimal";
        allowBreakingChanges?: boolean | undefined;
        targetBaseImage?: string | undefined;
    }, {
        strategy: "update_packages" | "change_base_image" | "minimal";
        allowBreakingChanges?: boolean | undefined;
        targetBaseImage?: string | undefined;
    }>>;
}, "strip", z.ZodTypeAny, {
    image: string;
    vulnerabilities: {
        id: string;
        severity: "critical" | "high" | "medium" | "low" | "info";
        package: string;
        installedVersion: string;
        fixAvailable: boolean;
        fixedVersion?: string | undefined;
    }[];
    dockerfile?: string | undefined;
    options?: {
        strategy: "update_packages" | "change_base_image" | "minimal";
        allowBreakingChanges?: boolean | undefined;
        targetBaseImage?: string | undefined;
    } | undefined;
}, {
    image: string;
    vulnerabilities: {
        id: string;
        severity: "critical" | "high" | "medium" | "low" | "info";
        package: string;
        installedVersion: string;
        fixAvailable: boolean;
        fixedVersion?: string | undefined;
    }[];
    dockerfile?: string | undefined;
    options?: {
        strategy: "update_packages" | "change_base_image" | "minimal";
        allowBreakingChanges?: boolean | undefined;
        targetBaseImage?: string | undefined;
    } | undefined;
}>;
export declare const kubernetesAnalyzeSchema: z.ZodObject<{
    content: z.ZodString;
}, "strip", z.ZodTypeAny, {
    content: string;
}, {
    content: string;
}>;
export declare const kubernetesGenerateSchema: z.ZodObject<{
    resourceType: z.ZodEnum<["Deployment", "Service", "Ingress", "ConfigMap", "Secret", "StatefulSet", "DaemonSet", "Job", "CronJob", "Namespace", "ServiceAccount", "Role", "RoleBinding", "NetworkPolicy", "PersistentVolumeClaim"]>;
    config: z.ZodRecord<z.ZodString, z.ZodUnknown>;
}, "strip", z.ZodTypeAny, {
    config: Record<string, unknown>;
    resourceType: "Deployment" | "Service" | "Ingress" | "ConfigMap" | "Secret" | "StatefulSet" | "DaemonSet" | "Job" | "CronJob" | "Namespace" | "ServiceAccount" | "Role" | "RoleBinding" | "NetworkPolicy" | "PersistentVolumeClaim";
}, {
    config: Record<string, unknown>;
    resourceType: "Deployment" | "Service" | "Ingress" | "ConfigMap" | "Secret" | "StatefulSet" | "DaemonSet" | "Job" | "CronJob" | "Namespace" | "ServiceAccount" | "Role" | "RoleBinding" | "NetworkPolicy" | "PersistentVolumeClaim";
}>;
export declare const jenkinsfileAnalyzeSchema: z.ZodObject<{
    content: z.ZodString;
}, "strip", z.ZodTypeAny, {
    content: string;
}, {
    content: string;
}>;
export declare const jenkinsfileGenerateSchema: z.ZodObject<{
    config: z.ZodObject<{
        application: z.ZodEnum<["nodejs", "python", "java", "go", "docker", "generic"]>;
        repositoryUrl: z.ZodString;
        buildTool: z.ZodEnum<["npm", "maven", "gradle", "pip", "make", "none"]>;
        testing: z.ZodBoolean;
        dockerBuild: z.ZodBoolean;
        securityScan: z.ZodBoolean;
        dockerPush: z.ZodBoolean;
        deployment: z.ZodEnum<["kubernetes", "vm", "none", "ecs", "cloudrun"]>;
        environments: z.ZodArray<z.ZodEnum<["dev", "staging", "production"]>, "many">;
        kubernetesConfig: z.ZodOptional<z.ZodRecord<z.ZodString, z.ZodUnknown>>;
    }, "strip", z.ZodTypeAny, {
        application: "nodejs" | "python" | "java" | "go" | "docker" | "generic";
        repositoryUrl: string;
        buildTool: "npm" | "maven" | "gradle" | "pip" | "make" | "none";
        testing: boolean;
        dockerBuild: boolean;
        securityScan: boolean;
        dockerPush: boolean;
        deployment: "kubernetes" | "none" | "vm" | "ecs" | "cloudrun";
        environments: ("dev" | "staging" | "production")[];
        kubernetesConfig?: Record<string, unknown> | undefined;
    }, {
        application: "nodejs" | "python" | "java" | "go" | "docker" | "generic";
        repositoryUrl: string;
        buildTool: "npm" | "maven" | "gradle" | "pip" | "make" | "none";
        testing: boolean;
        dockerBuild: boolean;
        securityScan: boolean;
        dockerPush: boolean;
        deployment: "kubernetes" | "none" | "vm" | "ecs" | "cloudrun";
        environments: ("dev" | "staging" | "production")[];
        kubernetesConfig?: Record<string, unknown> | undefined;
    }>;
}, "strip", z.ZodTypeAny, {
    config: {
        application: "nodejs" | "python" | "java" | "go" | "docker" | "generic";
        repositoryUrl: string;
        buildTool: "npm" | "maven" | "gradle" | "pip" | "make" | "none";
        testing: boolean;
        dockerBuild: boolean;
        securityScan: boolean;
        dockerPush: boolean;
        deployment: "kubernetes" | "none" | "vm" | "ecs" | "cloudrun";
        environments: ("dev" | "staging" | "production")[];
        kubernetesConfig?: Record<string, unknown> | undefined;
    };
}, {
    config: {
        application: "nodejs" | "python" | "java" | "go" | "docker" | "generic";
        repositoryUrl: string;
        buildTool: "npm" | "maven" | "gradle" | "pip" | "make" | "none";
        testing: boolean;
        dockerBuild: boolean;
        securityScan: boolean;
        dockerPush: boolean;
        deployment: "kubernetes" | "none" | "vm" | "ecs" | "cloudrun";
        environments: ("dev" | "staging" | "production")[];
        kubernetesConfig?: Record<string, unknown> | undefined;
    };
}>;
export declare const githubConnectSchema: z.ZodObject<{
    token: z.ZodString;
    url: z.ZodOptional<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    token: string;
    url?: string | undefined;
}, {
    token: string;
    url?: string | undefined;
}>;
export declare const githubScanSchema: z.ZodObject<{
    repoUrl: z.ZodString;
    branch: z.ZodDefault<z.ZodString>;
    scanTypes: z.ZodDefault<z.ZodArray<z.ZodEnum<["vulnerabilities", "secrets", "dependencies", "code"]>, "many">>;
}, "strip", z.ZodTypeAny, {
    repoUrl: string;
    branch: string;
    scanTypes: ("code" | "vulnerabilities" | "secrets" | "dependencies")[];
}, {
    repoUrl: string;
    branch?: string | undefined;
    scanTypes?: ("code" | "vulnerabilities" | "secrets" | "dependencies")[] | undefined;
}>;
export declare const logInvestigateSchema: z.ZodObject<{
    question: z.ZodString;
    logFileIds: z.ZodArray<z.ZodString, "many">;
    timeRange: z.ZodOptional<z.ZodObject<{
        start: z.ZodString;
        end: z.ZodString;
    }, "strip", z.ZodTypeAny, {
        start: string;
        end: string;
    }, {
        start: string;
        end: string;
    }>>;
}, "strip", z.ZodTypeAny, {
    question: string;
    logFileIds: string[];
    timeRange?: {
        start: string;
        end: string;
    } | undefined;
}, {
    question: string;
    logFileIds: string[];
    timeRange?: {
        start: string;
        end: string;
    } | undefined;
}>;
export declare const dependencyScanSchema: z.ZodObject<{
    repoUrl: z.ZodString;
    branch: z.ZodDefault<z.ZodString>;
}, "strip", z.ZodTypeAny, {
    repoUrl: string;
    branch: string;
}, {
    repoUrl: string;
    branch?: string | undefined;
}>;
export declare const dependencyFixSchema: z.ZodObject<{
    package: z.ZodString;
    currentVersion: z.ZodString;
    targetVersion: z.ZodString;
    manifestPath: z.ZodString;
    vulnerabilityIds: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
}, "strip", z.ZodTypeAny, {
    package: string;
    currentVersion: string;
    targetVersion: string;
    manifestPath: string;
    vulnerabilityIds?: string[] | undefined;
}, {
    package: string;
    currentVersion: string;
    targetVersion: string;
    manifestPath: string;
    vulnerabilityIds?: string[] | undefined;
}>;
export declare const createJobSchema: z.ZodObject<{
    type: z.ZodEnum<["dockerfile_scan", "dockerfile_fix", "docker_image_scan", "docker_image_fix", "kubernetes_scan", "kubernetes_fix", "kubernetes_generate", "jenkinsfile_scan", "jenkinsfile_fix", "jenkinsfile_generate", "github_repo_scan", "github_dependency_scan", "github_secret_scan", "github_code_scan", "log_investigation", "dependency_scan", "dependency_fix", "sbom_generation"]>;
    input: z.ZodRecord<z.ZodString, z.ZodUnknown>;
    priority: z.ZodDefault<z.ZodEnum<["low", "normal", "high"]>>;
}, "strip", z.ZodTypeAny, {
    type: "dockerfile_scan" | "dockerfile_fix" | "docker_image_scan" | "docker_image_fix" | "kubernetes_scan" | "kubernetes_fix" | "kubernetes_generate" | "jenkinsfile_scan" | "jenkinsfile_fix" | "jenkinsfile_generate" | "github_repo_scan" | "github_dependency_scan" | "github_secret_scan" | "github_code_scan" | "log_investigation" | "dependency_scan" | "dependency_fix" | "sbom_generation";
    input: Record<string, unknown>;
    priority: "high" | "low" | "normal";
}, {
    type: "dockerfile_scan" | "dockerfile_fix" | "docker_image_scan" | "docker_image_fix" | "kubernetes_scan" | "kubernetes_fix" | "kubernetes_generate" | "jenkinsfile_scan" | "jenkinsfile_fix" | "jenkinsfile_generate" | "github_repo_scan" | "github_dependency_scan" | "github_secret_scan" | "github_code_scan" | "log_investigation" | "dependency_scan" | "dependency_fix" | "sbom_generation";
    input: Record<string, unknown>;
    priority?: "high" | "low" | "normal" | undefined;
}>;
export declare const updateSettingsSchema: z.ZodObject<{
    ai: z.ZodOptional<z.ZodObject<{
        provider: z.ZodEnum<["apps_script", "openai", "gemini", "anthropic", "custom"]>;
        appsScriptUrl: z.ZodUnion<[z.ZodOptional<z.ZodString>, z.ZodLiteral<"">]>;
        defaultModel: z.ZodOptional<z.ZodString>;
        temperature: z.ZodOptional<z.ZodNumber>;
        maxTokens: z.ZodOptional<z.ZodNumber>;
    }, "strip", z.ZodTypeAny, {
        provider: "custom" | "apps_script" | "openai" | "gemini" | "anthropic";
        appsScriptUrl?: string | undefined;
        defaultModel?: string | undefined;
        temperature?: number | undefined;
        maxTokens?: number | undefined;
    }, {
        provider: "custom" | "apps_script" | "openai" | "gemini" | "anthropic";
        appsScriptUrl?: string | undefined;
        defaultModel?: string | undefined;
        temperature?: number | undefined;
        maxTokens?: number | undefined;
    }>>;
    scanning: z.ZodOptional<z.ZodObject<{
        maxConcurrentScans: z.ZodOptional<z.ZodNumber>;
        scanTimeout: z.ZodOptional<z.ZodNumber>;
        defaultTools: z.ZodOptional<z.ZodArray<z.ZodString, "many">>;
    }, "strip", z.ZodTypeAny, {
        maxConcurrentScans?: number | undefined;
        scanTimeout?: number | undefined;
        defaultTools?: string[] | undefined;
    }, {
        maxConcurrentScans?: number | undefined;
        scanTimeout?: number | undefined;
        defaultTools?: string[] | undefined;
    }>>;
    notifications: z.ZodOptional<z.ZodObject<{
        emailEnabled: z.ZodOptional<z.ZodBoolean>;
        fromEmail: z.ZodUnion<[z.ZodOptional<z.ZodString>, z.ZodLiteral<"">]>;
    }, "strip", z.ZodTypeAny, {
        emailEnabled?: boolean | undefined;
        fromEmail?: string | undefined;
    }, {
        emailEnabled?: boolean | undefined;
        fromEmail?: string | undefined;
    }>>;
}, "strip", z.ZodTypeAny, {
    ai?: {
        provider: "custom" | "apps_script" | "openai" | "gemini" | "anthropic";
        appsScriptUrl?: string | undefined;
        defaultModel?: string | undefined;
        temperature?: number | undefined;
        maxTokens?: number | undefined;
    } | undefined;
    scanning?: {
        maxConcurrentScans?: number | undefined;
        scanTimeout?: number | undefined;
        defaultTools?: string[] | undefined;
    } | undefined;
    notifications?: {
        emailEnabled?: boolean | undefined;
        fromEmail?: string | undefined;
    } | undefined;
}, {
    ai?: {
        provider: "custom" | "apps_script" | "openai" | "gemini" | "anthropic";
        appsScriptUrl?: string | undefined;
        defaultModel?: string | undefined;
        temperature?: number | undefined;
        maxTokens?: number | undefined;
    } | undefined;
    scanning?: {
        maxConcurrentScans?: number | undefined;
        scanTimeout?: number | undefined;
        defaultTools?: string[] | undefined;
    } | undefined;
    notifications?: {
        emailEnabled?: boolean | undefined;
        fromEmail?: string | undefined;
    } | undefined;
}>;
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
//# sourceMappingURL=index.d.ts.map