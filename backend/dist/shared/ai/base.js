"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseAIProvider = void 0;
class BaseAIProvider {
    config = {};
    models = [];
    async initialize(config) {
        this.config = config;
        // Resolve provider settings first: getDefaultModels() may depend on the
        // configured URL/key/model, so it must run after onInitialize().
        await this.onInitialize();
        this.models = this.getDefaultModels();
    }
    getModels() {
        return this.models;
    }
    async healthCheck() {
        try {
            const response = await this.complete({
                prompt: 'Health check',
                maxTokens: 10,
                temperature: 0
            });
            return !!response.content;
        }
        catch {
            return false;
        }
    }
    buildMessages(request) {
        const messages = [];
        if (request.systemPrompt) {
            messages.push({ role: 'system', content: request.systemPrompt });
        }
        // Add context if provided
        if (request.context) {
            messages.push({
                role: 'system',
                content: `Context: ${JSON.stringify(request.context)}`
            });
        }
        messages.push({ role: 'user', content: request.prompt });
        return messages;
    }
    parseStructuredResponse(content, schema) {
        try {
            // Try to extract JSON from the response
            const jsonMatch = content.match(/\{[\s\S]*\}/);
            if (jsonMatch) {
                const parsed = JSON.parse(jsonMatch[0]);
                return schema.parse(parsed);
            }
            return null;
        }
        catch {
            return null;
        }
    }
    createResponse(content, model, toolCalls, usage) {
        return {
            content,
            toolCalls,
            usage,
            model,
            finishReason: toolCalls?.length ? 'tool_calls' : 'stop'
        };
    }
}
exports.BaseAIProvider = BaseAIProvider;
