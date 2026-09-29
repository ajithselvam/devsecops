"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.aiRoutes = aiRoutes;
const ai_1 = require("../../shared/ai");
const audit_1 = require("../../shared/utils/audit");
const askSchema = {
    type: 'object',
    required: ['prompt'],
    properties: {
        prompt: { type: 'string', minLength: 1, maxLength: 10000 },
        context: { type: 'string' },
        model: { type: 'string' },
        temperature: { type: 'number', minimum: 0, maximum: 2 },
        maxTokens: { type: 'number' },
        systemPrompt: { type: 'string' }
    }
};
const fixSchema = {
    type: 'object',
    required: ['code', 'finding'],
    properties: {
        code: { type: 'string', minLength: 1 },
        language: { type: 'string' },
        finding: {
            type: 'object',
            required: ['type', 'severity', 'title', 'description'],
            properties: {
                type: { type: 'string' },
                severity: { type: 'string' },
                title: { type: 'string' },
                description: { type: 'string' },
                file: { type: 'string' },
                line: { type: 'number' },
                ruleId: { type: 'string' }
            }
        },
        context: { type: 'string' }
    }
};
const explainSchema = {
    type: 'object',
    required: ['code'],
    properties: {
        code: { type: 'string', minLength: 1 },
        language: { type: 'string' },
        focus: { type: 'string' }
    }
};
async function aiRoutes(app) {
    // Ask AI
    app.post('/ask', {
        preHandler: [app.authenticate],
        schema: { body: askSchema }
    }, async (request, reply) => {
        const userId = request.user.userId;
        const { prompt, context, model, temperature, maxTokens, systemPrompt } = request.body;
        try {
            const provider = (0, ai_1.getAIProvider)();
            const response = await provider.complete({
                prompt,
                context: context ? { additional: context } : undefined,
                model,
                temperature,
                maxTokens,
                systemPrompt
            });
            await (0, audit_1.auditLog)(request, 'AI_ASK', 'ai', undefined, { promptLength: prompt.length, model: model || 'default' });
            return { success: true, data: response };
        }
        catch (error) {
            return reply.code(500).send({ success: false, error: { code: 'AI_ERROR', message: error.message, statusCode: 500 } });
        }
    });
    // Generate fix for finding
    app.post('/fix', {
        preHandler: [app.authenticate],
        schema: { body: fixSchema }
    }, async (request, reply) => {
        const userId = request.user.userId;
        const { code, language, finding, context } = request.body;
        try {
            const provider = (0, ai_1.getAIProvider)();
            const fixPrompt = `You are a security expert. Generate a fix for the following security issue.

Finding:
- Type: ${finding.type}
- Severity: ${finding.severity}
- Title: ${finding.title}
- Description: ${finding.description}
${finding.file ? `- File: ${finding.file}` : ''}
${finding.line ? `- Line: ${finding.line}` : ''}
${finding.ruleId ? `- Rule: ${finding.ruleId}` : ''}

Code to fix:
\`\`\`${language || ''}
${code}
\`\`\`

${context ? `Additional context: ${context}` : ''}

Provide a JSON response with:
{
  "explanation": "Brief explanation of the fix",
  "patch": "Unified diff format patch",
  "confidence": 0-100,
  "steps": ["Step 1", "Step 2"]
}`;
            const response = await provider.complete({
                prompt: fixPrompt,
                systemPrompt: 'You are a security expert that generates safe, minimal fixes for security vulnerabilities. Always respond with valid JSON.',
                temperature: 0.2,
                maxTokens: 4096
            });
            await (0, audit_1.auditLog)(request, 'AI_FIX_GENERATED', 'ai', undefined, { findingType: finding.type, severity: finding.severity });
            return { success: true, data: response };
        }
        catch (error) {
            return reply.code(500).send({ success: false, error: { code: 'AI_ERROR', message: error.message, statusCode: 500 } });
        }
    });
    // Explain code
    app.post('/explain', {
        preHandler: [app.authenticate],
        schema: { body: explainSchema }
    }, async (request, reply) => {
        const userId = request.user.userId;
        const { code, language, focus } = request.body;
        try {
            const provider = (0, ai_1.getAIProvider)();
            const explainPrompt = `Explain the following ${language || 'code'} code${focus ? ` with focus on: ${focus}` : ''}:

\`\`\`${language || ''}
${code}
\`\`\`

Provide a clear, concise explanation covering:
1. What the code does
2. Security implications (if any)
3. Potential improvements`;
            const response = await provider.complete({
                prompt: explainPrompt,
                temperature: 0.3,
                maxTokens: 2048
            });
            await (0, audit_1.auditLog)(request, 'AI_EXPLAIN', 'ai', undefined, { language: language || 'unknown' });
            return { success: true, data: response };
        }
        catch (error) {
            return reply.code(500).send({ success: false, error: { code: 'AI_ERROR', message: error.message, statusCode: 500 } });
        }
    });
    // Get available models
    app.get('/models', {
        preHandler: [app.authenticate]
    }, async (request, reply) => {
        const provider = (0, ai_1.getAIProvider)();
        const models = provider.getModels();
        return { success: true, data: models };
    });
    // Test AI connection (public - for sidebar status indicator)
    app.get('/test', async (request, reply) => {
        try {
            const provider = (0, ai_1.getAIProvider)();
            const response = await provider.complete({ prompt: 'Say "OK" if you can hear me.', maxTokens: 10 });
            return { success: true, data: { connected: true, response } };
        }
        catch (error) {
            return { success: false, data: { connected: false, error: error.message } };
        }
    });
    // Test AI connection (authenticated - for detailed testing)
    app.get('/test-auth', {
        preHandler: [app.authenticate]
    }, async (request, reply) => {
        try {
            const provider = (0, ai_1.getAIProvider)();
            const response = await provider.complete({ prompt: 'Say "OK" if you can hear me.', maxTokens: 10 });
            return { success: true, data: { connected: true, response } };
        }
        catch (error) {
            return { success: false, data: { connected: false, error: error.message } };
        }
    });
}
