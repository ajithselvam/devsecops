import { AIProvider, AIRequest, AIResponse, AIModel, DockerfileFixResponse, KubernetesFixResponse, JenkinsfileFixResponse, LogInvestigationResponse, DependencyFixResponse, GitHubCodeFixResponse } from './types';
import { AIProviderConfig } from '@devsecops/shared/types';
import { AppsScriptProvider } from './providers/apps-script';
import { OmniRouteProvider } from './providers/omniroute';
import { FreeAIProvider } from './providers/freeai';
import { config } from '../config';
import { prisma } from '../database';

export class AIService {
  private providers: Map<string, AIProvider> = new Map();
  private defaultProvider: string = 'apps_script';
  private initialized = false;

  async initialize(): Promise<void> {
    if (this.initialized) return;

    const settings = await prisma.settings.findFirst();

    // ── free.ai (OpenAI-compatible, reachable in hosted environments) ─────────
    const freeAiKey = process.env.AI_FREE_AI_KEY;
    if (freeAiKey) {
      const freeAiProvider = new FreeAIProvider();
      await freeAiProvider.initialize({
        baseUrl: process.env.AI_FREE_AI_URL || config.AI_FREE_AI_URL,
        apiKey: freeAiKey,
        model: process.env.AI_FREE_AI_MODEL || config.AI_FREE_AI_MODEL,
      });
      this.providers.set('freeai', freeAiProvider);
      this.defaultProvider = 'freeai';
      console.log(`[AI] free.ai provider registered → ${process.env.AI_FREE_AI_URL || config.AI_FREE_AI_URL}`);
    }

    // ── OmniRoute (local server, kept as an alternative) ─────────────────────
    const omniUrl = process.env.AI_OMNIROUTE_URL || (settings as any)?.aiOmnirouteUrl;
    if (omniUrl) {
      const omniProvider = new OmniRouteProvider();
      await omniProvider.initialize({
        baseUrl: omniUrl,
        apiKey: process.env.AI_OMNIROUTE_KEY || (settings as any)?.aiOmnirouteKey || 'omniroute',
        model: process.env.AI_OMNIROUTE_MODEL || (settings as any)?.aiOmnirouteModel || 'auto',
      });
      this.providers.set('omniroute', omniProvider);
      // free.ai wins when configured; otherwise fall back to OmniRoute.
      if (!freeAiKey) {
        this.defaultProvider = 'omniroute';
      }
      console.log(`[AI] OmniRoute provider registered → ${omniUrl}`);
    }

    // ── Apps Script / OpenRouter bridge (last-resort fallback) ───────────────
    const appsScriptUrl = settings?.aiAppsScriptUrl || config.AI_APPS_SCRIPT_URL;
    if (appsScriptUrl) {
      try {
        const appsScriptProvider = new AppsScriptProvider();
        await appsScriptProvider.initialize({
          endpoint: appsScriptUrl,
          apiKey: settings?.aiOpenaiKey
        });
        this.providers.set('apps_script', appsScriptProvider);
        if (!omniUrl && !freeAiKey) {
          this.defaultProvider = 'apps_script';
          console.log(`[AI] Apps Script provider registered → ${appsScriptUrl}`);
        }
      } catch (err) {
        console.warn('[AI] Apps Script provider failed to initialize:', err);
      }
    }

    // An explicit AI_DEFAULT_PROVIDER overrides the preference order above,
    // which is how you switch back to a local OmniRoute server.
    const forced = config.AI_DEFAULT_PROVIDER;
    if (forced) {
      if (this.providers.has(forced)) {
        this.defaultProvider = forced;
        console.log(`[AI] Default provider forced to '${forced}' via AI_DEFAULT_PROVIDER`);
      } else {
        console.warn(`[AI] AI_DEFAULT_PROVIDER='${forced}' is not a registered provider; ignoring`);
      }
    }

    this.initialized = true;
  }

  getProvider(type?: string): AIProvider {
    const providerType = type || this.defaultProvider;
    const provider = this.providers.get(providerType);
    if (!provider) {
      throw new Error(
        `AI provider '${providerType}' not initialized. ` +
        (providerType === 'omniroute'
          ? 'Is your OmniRoute server running at http://localhost:20128?'
          : providerType === 'freeai'
          ? 'Is AI_FREE_AI_KEY set and is the free.ai endpoint reachable?'
          : 'Check your AI configuration.')
      );
    }
    return provider;
  }

  getAvailableProviders(): AIProviderConfig[] {
    return Array.from(this.providers.values()).map(p => ({
      type: p.type as 'apps_script' | 'openai' | 'gemini' | 'anthropic' | 'custom' | 'omniroute' | 'freeai',
      name: p.name,
      enabled: true,
      config: {},
      models: p.getModels(),
      defaultModel: p.getModels()[0]?.id || ''
    }));
  }

  setDefaultProvider(type: string): void {
    if (!this.providers.has(type)) {
      throw new Error(`Provider '${type}' not available`);
    }
    this.defaultProvider = type;
  }

  async complete(request: AIRequest, providerType?: string): Promise<AIResponse> {
    const provider = this.getProvider(providerType);
    return provider.complete(request);
  }

  async ask(data: {
    prompt: string;
    context?: string;
    model?: string;
    temperature?: number;
    maxTokens?: number;
    systemPrompt?: string;
  }): Promise<{ response: string; model: string; usage: any }> {
    const request: AIRequest = {
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

  async stream(request: AIRequest, onChunk: (chunk: string) => void, providerType?: string): Promise<AIResponse> {
    const provider = this.getProvider(providerType);
    return provider.stream(request, onChunk);
  }

  // Specialized methods — delegate to the active provider
  async fixDockerfile(dockerfile: string, issues: any[], options?: any): Promise<DockerfileFixResponse> {
    const provider = this.getProvider() as OmniRouteProvider | AppsScriptProvider;
    return provider.fixDockerfile(dockerfile, issues, options);
  }

  async fixKubernetes(yaml: string, issues: any[], options?: any): Promise<KubernetesFixResponse> {
    const provider = this.getProvider() as OmniRouteProvider | AppsScriptProvider;
    return provider.fixKubernetes(yaml, issues, options);
  }

  async fixJenkinsfile(jenkinsfile: string, issues: any[], options?: any): Promise<JenkinsfileFixResponse> {
    const provider = this.getProvider() as OmniRouteProvider | AppsScriptProvider;
    return provider.fixJenkinsfile(jenkinsfile, issues, options);
  }

  async investigateLogs(question: string, logEntries: any[], context?: any): Promise<LogInvestigationResponse> {
    const provider = this.getProvider() as OmniRouteProvider | AppsScriptProvider;
    return provider.investigateLogs(question, logEntries, context);
  }

  async fixDependency(pkg: string, currentVersion: string, targetVersion: string, vulnerabilities: any[], manifestContent: string): Promise<DependencyFixResponse> {
    const provider = this.getProvider() as OmniRouteProvider | AppsScriptProvider;
    return provider.fixDependency(pkg, currentVersion, targetVersion, vulnerabilities, manifestContent);
  }

  async fixGitHubCode(finding: any, fileContent: string, surroundingContext: string): Promise<GitHubCodeFixResponse> {
    const provider = this.getProvider() as OmniRouteProvider | AppsScriptProvider;
    return provider.fixGitHubCode(finding, fileContent, surroundingContext);
  }

  async healthCheck(): Promise<Record<string, boolean>> {
    const results: Record<string, boolean> = {};
    for (const [type, provider] of this.providers) {
      results[type] = await provider.healthCheck();
    }
    return results;
  }
}

export const aiService = new AIService();

export function getAIProvider(): AIProvider {
  return aiService.getProvider();
}