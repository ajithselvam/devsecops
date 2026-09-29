export declare const SEVERITY_LEVELS: readonly ["critical", "high", "medium", "low", "info"];
export declare const SEVERITY_COLORS: Record<string, string>;
export declare const SEVERITY_RANK: Record<string, number>;
export declare const JOB_STATUS_LABELS: Record<string, string>;
export declare const SCAN_TYPES: readonly ["dockerfile", "docker_image", "kubernetes", "jenkinsfile", "github_repo", "dependency", "logs"];
export declare const SIDEBAR_SECTIONS: readonly [{
    readonly id: "dashboard";
    readonly label: "Dashboard";
    readonly icon: "LayoutDashboard";
}, {
    readonly id: "dockerfile";
    readonly label: "Dockerfile AI Fixer";
    readonly icon: "Container";
}, {
    readonly id: "docker";
    readonly label: "Docker Image Scanner";
    readonly icon: "ShieldCheck";
}, {
    readonly id: "kubernetes";
    readonly label: "Kubernetes YAML AI";
    readonly icon: "Boxes";
}, {
    readonly id: "jenkins";
    readonly label: "Jenkins AI Assistant";
    readonly icon: "GitBranch";
}, {
    readonly id: "github";
    readonly label: "GitHub Security";
    readonly icon: "Github";
}, {
    readonly id: "logs";
    readonly label: "AI Log Investigation";
    readonly icon: "FileSearch";
}, {
    readonly id: "dependencies";
    readonly label: "Dependency Risk Radar";
    readonly icon: "Radar";
}, {
    readonly id: "scans";
    readonly label: "Scan History";
    readonly icon: "History";
}, {
    readonly id: "settings";
    readonly label: "Settings";
    readonly icon: "Settings";
}];
export declare const SUPPORTED_FILE_TYPES: {
    dockerfile: string[];
    yaml: string[];
    jenkinsfile: string[];
    logs: string[];
    manifest: string[];
};
export declare const MAX_FILE_SIZE: number;
export declare const RATE_LIMITS: {
    api: {
        windowMs: number;
        maxRequests: number;
    };
    upload: {
        windowMs: number;
        maxRequests: number;
    };
    ai: {
        windowMs: number;
        maxRequests: number;
    };
};
export declare const AI_PROVIDERS: {
    apps_script: {
        name: string;
        description: string;
        defaultModel: string;
        requiresApiKey: boolean;
    };
    openai: {
        name: string;
        description: string;
        defaultModel: string;
        requiresApiKey: boolean;
    };
    gemini: {
        name: string;
        description: string;
        defaultModel: string;
        requiresApiKey: boolean;
    };
    anthropic: {
        name: string;
        description: string;
        defaultModel: string;
        requiresApiKey: boolean;
    };
};
export declare const NODE_ENV: string;
export declare const SUPPORTED_LANGUAGES: string[];
//# sourceMappingURL=index.d.ts.map