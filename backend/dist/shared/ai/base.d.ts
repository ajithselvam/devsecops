import { AIProvider, AIRequest, AIResponse, AIModel, AIToolCall } from './types';
export declare abstract class BaseAIProvider implements AIProvider {
    abstract name: string;
    abstract type: string;
    protected config: Record<string, unknown>;
    protected models: AIModel[];
    initialize(config: Record<string, unknown>): Promise<void>;
    protected abstract onInitialize(): Promise<void>;
    protected abstract getDefaultModels(): AIModel[];
    abstract complete(request: AIRequest): Promise<AIResponse>;
    abstract stream(request: AIRequest, onChunk: (chunk: string) => void): Promise<AIResponse>;
    getModels(): AIModel[];
    healthCheck(): Promise<boolean>;
    protected buildMessages(request: AIRequest): Array<{
        role: string;
        content: string;
    }>;
    protected parseStructuredResponse<T>(content: string, schema: any): T | null;
    protected createResponse(content: string, model: string, toolCalls?: AIToolCall[], usage?: {
        promptTokens: number;
        completionTokens: number;
        totalTokens: number;
    }): AIResponse;
}
//# sourceMappingURL=base.d.ts.map