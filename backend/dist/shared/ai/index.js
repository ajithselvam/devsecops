"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.aiService = exports.AIService = void 0;
exports.getAIProvider = getAIProvider;
const apps_script_1 = require("./providers/apps-script");
const omniroute_1 = require("./providers/omniroute");
const freeai_1 = require("./providers/freeai");
const config_1 = require("../config");
const database_1 = require("../database");
class AIService {
    providers = new Map();
    defaultProvider = 'apps_script';
    initialized = false;
    async initialize() {
        if (this.initialized)
            return;
        const settings = await database_1.prisma.settings.findFirst();
        // ── free.ai (OpenAI-compatible, reachable in hosted environments) ─────────
        const freeAiKey = process.env.AI_FREE_AI_KEY;
        if (freeAiKey) {
            const freeAiProvider = new freeai_1.FreeAIProvider();
            await freeAiProvider.initialize({
                baseUrl: process.env.AI_FREE_AI_URL || config_1.config.AI_FREE_AI_URL,
                apiKey: freeAiKey,
                model: process.env.AI_FREE_AI_MODEL || config_1.config.AI_FREE_AI_MODEL,
            });
            this.providers.set('freeai', freeAiProvider);
            this.defaultProvider = 'freeai';
            console.log(`[AI] free.ai provider registered → ${process.env.AI_FREE_AI_URL || config_1.config.AI_FREE_AI_URL}`);
        }
        // ── OmniRoute (local server, kept as an alternative) ─────────────────────
        const omniUrl = process.env.AI_OMNIROUTE_URL || settings?.aiOmnirouteUrl;
        if (omniUrl) {
            const omniProvider = new omniroute_1.OmniRouteProvider();
            await omniProvider.initialize({
                baseUrl: omniUrl,
                apiKey: process.env.AI_OMNIROUTE_KEY || settings?.aiOmnirouteKey || 'omniroute',
                model: process.env.AI_OMNIROUTE_MODEL || settings?.aiOmnirouteModel || 'auto',
            });
            this.providers.set('omniroute', omniProvider);
            // free.ai wins when configured; otherwise fall back to OmniRoute.
            if (!freeAiKey) {
                this.defaultProvider = 'omniroute';
            }
            console.log(`[AI] OmniRoute provider registered → ${omniUrl}`);
        }
        // ── Apps Script / OpenRouter bridge (last-resort fallback) ───────────────
        const appsScriptUrl = settings?.aiAppsScriptUrl || config_1.config.AI_APPS_SCRIPT_URL;
        if (appsScriptUrl) {
            try {
                const appsScriptProvider = new apps_script_1.AppsScriptProvider();
                await appsScriptProvider.initialize({
                    endpoint: appsScriptUrl,
                    apiKey: settings?.aiOpenaiKey
                });
                this.providers.set('apps_script', appsScriptProvider);
                if (!omniUrl && !freeAiKey) {
                    this.defaultProvider = 'apps_script';
                    console.log(`[AI] Apps Script provider registered → ${appsScriptUrl}`);
                }
            }
            catch (err) {
                console.warn('[AI] Apps Script provider failed to initialize:', err);
            }
        }
        // An explicit AI_DEFAULT_PROVIDER overrides the preference order above,
        // which is how you switch back to a local OmniRoute server.
        const forced = config_1.config.AI_DEFAULT_PROVIDER;
        if (forced) {
            if (this.providers.has(forced)) {
                this.defaultProvider = forced;
                console.log(`[AI] Default provider forced to '${forced}' via AI_DEFAULT_PROVIDER`);
            }
            else {
                console.warn(`[AI] AI_DEFAULT_PROVIDER='${forced}' is not a registered provider; ignoring`);
            }
        }
        this.initialized = true;
    }
    getProvider(type) {
        const providerType = type || this.defaultProvider;
        const provider = this.providers.get(providerType);
        if (!provider) {
            throw new Error(`AI provider '${providerType}' not initialized. ` +
                (providerType === 'omniroute'
                    ? 'Is your OmniRoute server running at http://localhost:20128?'
                    : providerType === 'freeai'
                        ? 'Is AI_FREE_AI_KEY set and is the free.ai endpoint reachable?'
                        : 'Check your AI configuration.'));
        }
        return provider;
    }
    getAvailableProviders() {
        return Array.from(this.providers.values()).map(p => ({
            type: p.type,
            name: p.name,
            enabled: true,
            config: {},
            models: p.getModels(),
            defaultModel: p.getModels()[0]?.id || ''
        }));
    }
    setDefaultProvider(type) {
        if (!this.providers.has(type)) {
            throw new Error(`Provider '${type}' not available`);
        }
        this.defaultProvider = type;
    }
    async complete(request, providerType) {
        const provider = this.getProvider(providerType);
        return provider.complete(request);
    }
    async ask(data) {
        const request = {
            prompt: data.prompt,
            context: data.context ? { additional: data.context } : undefined,
            model: data.model,
            temperature: data.temperature,
            maxTokens: data.maxTokens,
            systemPrompt: data.systemPrompt
        };
        const result = await this.complete(request);
        return { response: result.content, model: result.model, usage: result.usage };
    }
    async stream(request, onChunk, providerType) {
        const provider = this.getProvider(providerType);
        return provider.stream(request, onChunk);
    }
    // Specialized methods — delegate to the active provider
    async fixDockerfile(dockerfile, issues, options) {
        const provider = this.getProvider();
        return provider.fixDockerfile(dockerfile, issues, options);
    }
    async fixKubernetes(yaml, issues, options) {
        const provider = this.getProvider();
        return provider.fixKubernetes(yaml, issues, options);
    }
    async fixJenkinsfile(jenkinsfile, issues, options) {
        const provider = this.getProvider();
        return provider.fixJenkinsfile(jenkinsfile, issues, options);
    }
    async investigateLogs(question, logEntries, context) {
        const provider = this.getProvider();
        return provider.investigateLogs(question, logEntries, context);
    }
    async fixDependency(pkg, currentVersion, targetVersion, vulnerabilities, manifestContent) {
        const provider = this.getProvider();
        return provider.fixDependency(pkg, currentVersion, targetVersion, vulnerabilities, manifestContent);
    }
    async fixGitHubCode(finding, fileContent, surroundingContext) {
        const provider = this.getProvider();
        return provider.fixGitHubCode(finding, fileContent, surroundingContext);
    }
    async healthCheck() {
        const results = {};
        for (const [type, provider] of this.providers) {
            results[type] = await provider.healthCheck();
        }
        return results;
    }
}
exports.AIService = AIService;
exports.aiService = new AIService();
function getAIProvider() {
    return exports.aiService.getProvider();
}
