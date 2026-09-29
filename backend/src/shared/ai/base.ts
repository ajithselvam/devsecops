import { AIProvider, AIRequest, AIResponse, AIModel, AIToolCall } from './types';

export abstract class BaseAIProvider implements AIProvider {
  abstract name: string;
  abstract type: string;
  protected config: Record<string, unknown> = {};
  protected models: AIModel[] = [];

  async initialize(config: Record<string, unknown>): Promise<void> {
    this.config = config;
    // Resolve provider settings first: getDefaultModels() may depend on the
    // configured URL/key/model, so it must run after onInitialize().
    await this.onInitialize();
    this.models = this.getDefaultModels();
  }

  protected abstract onInitialize(): Promise<void>;
  protected abstract getDefaultModels(): AIModel[];

  abstract complete(request: AIRequest): Promise<AIResponse>;
  abstract stream(request: AIRequest, onChunk: (chunk: string) => void): Promise<AIResponse>;

  getModels(): AIModel[] {
    return this.models;
  }

  async healthCheck(): Promise<boolean> {
    try {
      const response = await this.complete({
        prompt: 'Health check',
        maxTokens: 10,
        temperature: 0
      });
      return !!response.content;
    } catch {
      return false;
    }
  }

  protected buildMessages(request: AIRequest): Array<{ role: string; content: string }> {
    const messages: Array<{ role: string; content: string }> = [];

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

  protected parseStructuredResponse<T>(content: string, schema: any): T | null {
    try {
      // Try to extract JSON from the response
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        const parsed = JSON.parse(jsonMatch[0]);
        return schema.parse(parsed);
      }
      return null;
    } catch {
      return null;
    }
  }

  protected createResponse(
    content: string,
    model: string,
    toolCalls?: AIToolCall[],
    usage?: { promptTokens: number; completionTokens: number; totalTokens: number }
  ): AIResponse {
    return {
      content,
      toolCalls,
      usage,
      model,
      finishReason: toolCalls?.length ? 'tool_calls' : 'stop'
    };
  }
}