"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.FreeAIProvider = void 0;
const omniroute_1 = require("./omniroute");
/**
 * Free.ai Provider
 *
 * free.ai exposes an OpenAI-compatible chat endpoint, so this reuses the
 * OmniRoute client (same request/response handling and the same structured
 * fix/investigate helpers) and only swaps the URL, key and model.
 *
 * Config (via .env):
 *   AI_FREE_AI_URL   = https://api.free.ai/v1/chat/
 *   AI_FREE_AI_KEY   = sk-free-...
 *   AI_FREE_AI_MODEL = qwen7b
 *
 * Unlike OmniRoute this is reachable from hosted environments, so it is the
 * provider used in production. OmniRoute stays registered as an alternative.
 */
class FreeAIProvider extends omniroute_1.OmniRouteProvider {
    name = 'Free.ai (Qwen)';
    type = 'freeai';
    /** qwen7b is a small model, so keep completions well under its context. */
    maxOutputTokens = 4096;
    get connectionHint() {
        return `check AI_FREE_AI_KEY and that ${this.chatUrl} is reachable.`;
    }
    /**
     * free.ai serves chat at the configured URL itself, so do not append the
     * OpenAI `/chat/completions` suffix.
     */
    get chatUrl() {
        return this.baseUrl;
    }
    async onInitialize() {
        this.baseUrl = (this.config.baseUrl || process.env.AI_FREE_AI_URL || 'https://api.free.ai/v1/chat/')
            .replace(/\/$/, '');
        this.apiKey = this.config.apiKey || process.env.AI_FREE_AI_KEY || '';
        this.defaultModel = this.config.model || process.env.AI_FREE_AI_MODEL || 'qwen7b';
    }
    getDefaultModels() {
        return [
            {
                id: this.defaultModel || 'qwen7b',
                name: `Qwen (${this.defaultModel || 'qwen7b'}) via free.ai`,
                maxTokens: this.maxOutputTokens,
                supportsStreaming: false,
                supportsTools: false
            }
        ];
    }
}
exports.FreeAIProvider = FreeAIProvider;
