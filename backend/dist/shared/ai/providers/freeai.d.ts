import { OmniRouteProvider } from './omniroute';
import { AIModel } from '../types';
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
export declare class FreeAIProvider extends OmniRouteProvider {
    name: string;
    type: string;
    /** qwen7b is a small model, so keep completions well under its context. */
    protected maxOutputTokens: number;
    protected get connectionHint(): string;
    /**
     * free.ai serves chat at the configured URL itself, so do not append the
     * OpenAI `/chat/completions` suffix.
     */
    protected get chatUrl(): string;
    protected onInitialize(): Promise<void>;
    protected getDefaultModels(): AIModel[];
}
//# sourceMappingURL=freeai.d.ts.map