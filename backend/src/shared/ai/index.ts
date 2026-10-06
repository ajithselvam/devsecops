import { AIProvider, AIRequest, AIResponse, AIModel, DockerfileFixResponse, KubernetesFixResponse, JenkinsfileFixResponse, LogInvestigationResponse, DependencyFixResponse, GitHubCodeFixResponse } from './types';
import { AIProviderConfig } from '@devsecops/shared/types';
import { AppsScriptProvider } from './providers/apps-script';
import { OmniRouteProvider } from './providers/omniroute';
import { FreeAIProvider } from './providers/freeai';
import { config } from '../config';
import { prisma } from '../database';

/** The structured-task surface shared by every provider that implements it. */
type StructuredAIProvider = Pick<
  OmniRouteProvider,
  'fixDockerfile' | 'fixKubernetes' | 'fixJenkinsfile' | 'investigateLogs' | 'fixDependency' | 'fixGitHubCode'
>;

export class AIService {
  private providers: Map<string, AIProvider> = new Map();
  private defaultProvider: string = 'apps_script';
  private initialized = false;

  /**
   * Providers are tried in this order for every request, so a provider that is
   * configured but unreachable (a stopped OmniRoute server, a revoked free.ai
   * key) degrades to the next one instead of failing the whole scan.
   */
  private providerOrder: string[] = [];

  /** Provider type → epoch ms before which it is skipped. */
  private cooldowns: Map<string, number> = new Map();
  private static readonly COOLDOWN_MS = 60000;
  private static readonly BASE_ORDER = ['freeai', 'omniroute', 'apps_script'];

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

    this.buildProviderOrder();

    this.initialized = true;
  }

  /**
   * The default provider leads the chain, then any provider named in
   * AI_PROVIDER_ORDER, then the remaining registered providers in the base
   * preference order. Unregistered names are dropped so a typo cannot shadow
   * a working provider.
   */
  private buildProviderOrder(): void {
    const explicit = config.AI_PROVIDER_ORDER
      .split(',')
      .map(name => name.trim())
      .filter(Boolean);
    const remainder = AIService.BASE_ORDER.filter(
      type => type !== this.defaultProvider && this.providers.has(type)
    );
    const unknown = [...explicit, this.defaultProvider].filter(type => !this.providers.has(type));
    if (unknown.length) {
      console.warn(`[AI] Ignoring unregistered provider(s) in the failover chain: ${unknown.join(', ')}`);
    }
    this.providerOrder = [
      ...new Set([this.defaultProvider, ...explicit, ...remainder])
    ].filter(type => this.providers.has(type));
    console.log(`[AI] Provider failover chain → ${this.providerOrder.join(' → ')}`);
  }

  /**
   * Registered providers that are not currently in a failure cooldown. Falls
   * back to the default provider alone so the chain is never empty.
   */
  getProviderChain(): string[] {
    const now = Date.now();
    const ready = this.providerOrder.filter(type => (this.cooldowns.get(type) ?? 0) <= now);
    return ready.length > 0 ? ready : [this.defaultProvider];
  }

  /** Preferred provider in the current chain, used for model listings. */
  getPreferredProviderType(): string {
    return this.getProviderChain()[0];
  }

  /**
   * Tries each provider in the chain until one answers, cooling down the ones
   * that fail so a dead endpoint is not retried on every request.
   */
  private async runWithFailover<T>(label: string, fn: (provider: AIProvider) => Promise<T>): Promise<T> {
    const chain = this.getProviderChain();
    const failures: string[] = [];

    for (const type of chain) {
      const provider = this.providers.get(type);
      if (!provider) continue;
      try {
        return await fn(provider);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.warn(`[AI] ${label} via '${type}' failed: ${message}`);
        failures.push(`${type}: ${message}`);
        this.cooldowns.set(type, Date.now() + AIService.COOLDOWN_MS);
      }
    }

    throw new Error(`All AI providers failed. ${failures.join(' ; ')}`);
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
    // An explicit providerType is a caller decision — no failover.
    if (providerType) {
      return this.getProvider(providerType).complete(request);
    }
    return this.runWithFailover('complete', provider => provider.complete(request));
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
    if (providerType) {
      return this.getProvider(providerType).stream(request, onChunk);
    }
    return this.runWithFailover('stream', provider => provider.stream(request, onChunk));
  }

  // Structured responses for specific tasks — each one fails over independently
  private async withStructuredProvider<T>(
    label: string,
    fn: (provider: StructuredAIProvider) => Promise<T>
  ): Promise<T> {
    return this.runWithFailover(label, provider => fn(provider as unknown as StructuredAIProvider));
  }

  async fixDockerfile(dockerfile: string, issues: any[], options?: any): Promise<DockerfileFixResponse> {
    return this.withStructuredProvider('fixDockerfile', p => p.fixDockerfile(dockerfile, issues, options));
  }

  async fixKubernetes(yaml: string, issues: any[], options?: any): Promise<KubernetesFixResponse> {
    return this.withStructuredProvider('fixKubernetes', p => p.fixKubernetes(yaml, issues, options));
  }

  async fixJenkinsfile(jenkinsfile: string, issues: any[], options?: any): Promise<JenkinsfileFixResponse> {
    return this.withStructuredProvider('fixJenkinsfile', p => p.fixJenkinsfile(jenkinsfile, issues, options));
  }

  async investigateLogs(question: string, logEntries: any[], context?: any): Promise<LogInvestigationResponse> {
    return this.withStructuredProvider('investigateLogs', p => p.investigateLogs(question, logEntries, context));
  }

  async fixDependency(pkg: string, currentVersion: string, targetVersion: string, vulnerabilities: any[], manifestContent: string): Promise<DependencyFixResponse> {
    return this.withStructuredProvider('fixDependency', p =>
      p.fixDependency(pkg, currentVersion, targetVersion, vulnerabilities, manifestContent)
    );
  }

  async fixGitHubCode(finding: any, fileContent: string, surroundingContext: string): Promise<GitHubCodeFixResponse> {
    return this.withStructuredProvider('fixGitHubCode', p => p.fixGitHubCode(finding, fileContent, surroundingContext));
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

export function getAIProvider(type?: string): AIProvider {
  return aiService.getProvider(type);
}
