"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SUPPORTED_LANGUAGES = exports.NODE_ENV = exports.AI_PROVIDERS = exports.RATE_LIMITS = exports.MAX_FILE_SIZE = exports.SUPPORTED_FILE_TYPES = exports.SIDEBAR_SECTIONS = exports.SCAN_TYPES = exports.JOB_STATUS_LABELS = exports.SEVERITY_RANK = exports.SEVERITY_COLORS = exports.SEVERITY_LEVELS = void 0;
exports.SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info'];
exports.SEVERITY_COLORS = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#3b82f6',
    info: '#6b7280'
};
exports.SEVERITY_RANK = {
    critical: 5,
    high: 4,
    medium: 3,
    low: 2,
    info: 1
};
exports.JOB_STATUS_LABELS = {
    queued: 'Queued',
    running: 'Running',
    analyzing: 'Analyzing',
    fixing: 'Fixing',
    completed: 'Completed',
    failed: 'Failed',
    cancelled: 'Cancelled'
};
exports.SCAN_TYPES = [
    'dockerfile',
    'docker_image',
    'kubernetes',
    'jenkinsfile',
    'github_repo',
    'dependency',
    'logs'
];
exports.SIDEBAR_SECTIONS = [
    { id: 'dashboard', label: 'Dashboard', icon: 'LayoutDashboard' },
    { id: 'dockerfile', label: 'Dockerfile AI Fixer', icon: 'Container' },
    { id: 'docker', label: 'Docker Image Scanner', icon: 'ShieldCheck' },
    { id: 'kubernetes', label: 'Kubernetes YAML AI', icon: 'Boxes' },
    { id: 'jenkins', label: 'Jenkins AI Assistant', icon: 'GitBranch' },
    { id: 'github', label: 'GitHub Security', icon: 'Github' },
    { id: 'logs', label: 'AI Log Investigation', icon: 'FileSearch' },
    { id: 'dependencies', label: 'Dependency Risk Radar', icon: 'Radar' },
    { id: 'scans', label: 'Scan History', icon: 'History' },
    { id: 'settings', label: 'Settings', icon: 'Settings' }
];
exports.SUPPORTED_FILE_TYPES = {
    'dockerfile': ['.dockerfile', 'Dockerfile', 'dockerfile'],
    'yaml': ['.yaml', '.yml'],
    'jenkinsfile': ['.jenkinsfile', 'Jenkinsfile', 'jenkinsfile'],
    'logs': ['.log', '.txt', '.json', '.gz'],
    'manifest': ['.json', '.txt', '.lock', '.xml', '.gradle', '.mod', '.sum', '.toml']
};
exports.MAX_FILE_SIZE = 25 * 1024 * 1024; // 25MB
exports.RATE_LIMITS = {
    api: { windowMs: 60 * 1000, maxRequests: 100 },
    upload: { windowMs: 60 * 1000, maxRequests: 10 },
    ai: { windowMs: 60 * 1000, maxRequests: 20 }
};
exports.AI_PROVIDERS = {
    apps_script: {
        name: 'Google Apps Script (Gemini Bridge)',
        description: 'Default provider using the configured Apps Script endpoint as an AI bridge',
        defaultModel: 'gemini-pro',
        requiresApiKey: false
    },
    openai: {
        name: 'OpenAI',
        description: 'OpenAI GPT models',
        defaultModel: 'gpt-4-turbo',
        requiresApiKey: true
    },
    gemini: {
        name: 'Google Gemini',
        description: 'Google Gemini models',
        defaultModel: 'gemini-1.5-pro',
        requiresApiKey: true
    },
    anthropic: {
        name: 'Anthropic Claude',
        description: 'Anthropic Claude models',
        defaultModel: 'claude-3-opus',
        requiresApiKey: true
    }
};
exports.NODE_ENV = process.env.NODE_ENV || 'development';
exports.SUPPORTED_LANGUAGES = [
    'javascript',
    'typescript',
    'python',
    'java',
    'go',
    'rust',
    'ruby',
    'php',
    'csharp',
    'cpp',
    'yaml',
    'dockerfile',
    'json',
    'bash',
    'sql'
];
