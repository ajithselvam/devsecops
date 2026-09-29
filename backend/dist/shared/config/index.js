"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.config = void 0;
require("dotenv/config");
exports.config = {
    NODE_ENV: process.env.NODE_ENV || 'development',
    PORT: parseInt(process.env.PORT || '3001', 10),
    HOST: process.env.HOST || '0.0.0.0',
    APP_VERSION: process.env.npm_package_version || '1.0.0',
    // Database
    // InsForge (auth, database, storage). The admin API key is server-only and
    // must never reach the browser bundle.
    INSFORGE_URL: process.env.INSFORGE_URL || '',
    INSFORGE_API_KEY: process.env.INSFORGE_API_KEY || '',
    INSFORGE_ANON_KEY: process.env.INSFORGE_ANON_KEY || '',
    INSFORGE_JWT_SECRET: process.env.INSFORGE_JWT_SECRET || '',
    /** PEM public key; InsForge access tokens are RS256 with a rotating `kid`. */
    INSFORGE_JWT_PUBLIC_KEY: process.env.INSFORGE_JWT_PUBLIC_KEY || '',
    INSFORGE_PROJECT_ID: process.env.INSFORGE_PROJECT_ID || '',
    INSFORGE_LOG_BUCKET: process.env.INSFORGE_LOG_BUCKET || 'log-files',
    INSFORGE_ARTIFACT_BUCKET: process.env.INSFORGE_ARTIFACT_BUCKET || 'scan-artifacts',
    // JWT
    JWT_SECRET: process.env.JWT_SECRET || 'dev-secret-change-in-production-min-32-chars!!',
    JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '7d',
    JWT_REFRESH_EXPIRES_IN: process.env.JWT_REFRESH_EXPIRES_IN || '30d',
    // CORS
    CORS_ORIGIN: process.env.CORS_ORIGIN || 'http://localhost:5173',
    // Rate limiting
    RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX || '1000', 10),
    RATE_LIMIT_WINDOW: parseInt(process.env.RATE_LIMIT_WINDOW || '60000', 10),
    // File uploads
    MAX_FILE_SIZE: parseInt(process.env.MAX_FILE_SIZE || '26214400', 10), // 25MB
    UPLOAD_DIR: process.env.UPLOAD_DIR || './uploads',
    // Redis
    REDIS_URL: process.env.REDIS_URL || 'redis://localhost:6379',
    // Scan/fix jobs are queued through Redis. Set QUEUE_ENABLED=false to run
    // the API without a queue (auth, listings, logs and exports still work).
    QUEUE_ENABLED: (process.env.QUEUE_ENABLED ?? 'true') === 'true',
    // AI Providers
    AI_OMNIROUTE_URL: process.env.AI_OMNIROUTE_URL || '', // OmniRoute local server
    AI_OMNIROUTE_KEY: process.env.AI_OMNIROUTE_KEY || 'omniroute', // OmniRoute API key
    AI_OMNIROUTE_MODEL: process.env.AI_OMNIROUTE_MODEL || 'auto', // OmniRoute model
    // free.ai OpenAI-compatible chat endpoint (used in hosted environments
    // where a local OmniRoute server is not reachable).
    AI_FREE_AI_URL: process.env.AI_FREE_AI_URL || 'https://api.free.ai/v1/chat/',
    AI_FREE_AI_KEY: process.env.AI_FREE_AI_KEY || '', // sk-free-...
    AI_FREE_AI_MODEL: process.env.AI_FREE_AI_MODEL || 'qwen7b', // free.ai model id
    // Forces which registered provider is the default. Unset = auto preference.
    AI_DEFAULT_PROVIDER: process.env.AI_DEFAULT_PROVIDER || '',
    AI_APPS_SCRIPT_URL: process.env.AI_APPS_SCRIPT_URL || '', // Apps Script bridge (fallback)
    AI_OPENAI_KEY: process.env.AI_OPENAI_KEY,
    AI_GEMINI_KEY: process.env.AI_GEMINI_KEY,
    AI_ANTHROPIC_KEY: process.env.AI_ANTHROPIC_KEY,
    // Docker
    DOCKER_SOCKET: process.env.DOCKER_SOCKET || '/var/run/docker.sock',
    // Scanning tools paths
    GRYPE_PATH: process.env.GRYPE_PATH || 'grype',
    SYFT_PATH: process.env.SYFT_PATH || 'syft',
    TRIVY_PATH: process.env.TRIVY_PATH || 'trivy',
    SEMGREP_PATH: process.env.SEMGREP_PATH || 'semgrep',
    GITLEAKS_PATH: process.env.GITLEAKS_PATH || 'gitleaks',
    // Queue
    QUEUE_CONCURRENCY: parseInt(process.env.QUEUE_CONCURRENCY || '3', 10),
    JOB_TIMEOUT: parseInt(process.env.JOB_TIMEOUT || '600000', 10), // 10 minutes
    // WebSocket
    WS_HEARTBEAT_INTERVAL: parseInt(process.env.WS_HEARTBEAT_INTERVAL || '30000', 10),
    // Security
    BCRYPT_ROUNDS: parseInt(process.env.BCRYPT_ROUNDS || '12', 10),
    SESSION_TIMEOUT: parseInt(process.env.SESSION_TIMEOUT || '604800000', 10), // 7 days
    MAX_LOGIN_ATTEMPTS: parseInt(process.env.MAX_LOGIN_ATTEMPTS || '5', 10),
    LOCKOUT_DURATION: parseInt(process.env.LOCKOUT_DURATION || '900000', 10), // 15 minutes
};
