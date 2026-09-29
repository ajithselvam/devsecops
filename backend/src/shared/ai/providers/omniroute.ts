import { BaseAIProvider } from '../base';
import {
  AIRequest, AIResponse, AIModel,
  DockerfileFixResponse, KubernetesFixResponse,
  JenkinsfileFixResponse, LogInvestigationResponse,
  DependencyFixResponse, GitHubCodeFixResponse
} from '../types';

/**
 * OmniRoute Provider
 *
 * Connects directly to a locally-hosted OmniRoute server which exposes an
 * OpenAI-compatible API (http://localhost:20128/v1).
 *
 * OmniRoute acts as a local AI router/proxy with no rate limits.
 * Start your OmniRoute server before using AI features.
 *
 * Config (via .env):
 *   AI_OMNIROUTE_URL   = http://localhost:20128/v1
 *   AI_OMNIROUTE_KEY   = omniroute   (or your actual key)
 *   AI_OMNIROUTE_MODEL = auto        (or any model your OmniRoute serves)
 */
export class OmniRouteProvider extends BaseAIProvider {
  name = 'OmniRoute (Local)';
  type = 'omniroute';

  // `protected` (not `private`) so sibling OpenAI-compatible providers such as
  // FreeAIProvider can reuse this client and override only URL/key/model.
  protected baseUrl: string = 'http://localhost:20128/v1';
  protected apiKey: string = 'omniroute';
  protected defaultModel: string = 'auto';

  /** Cap used when a caller does not request a specific size. */
  protected maxOutputTokens: number = 16384;
  /** Extra context appended to connection errors. */
  protected get connectionHint(): string {
    return 'is your OmniRoute server running at http://localhost:20128?';
  }

  /** Absolute chat-completions URL for this provider. */
  protected get chatUrl(): string {
    return `${this.baseUrl}/chat/completions`;
  }

  protected async onInitialize(): Promise<void> {
    this.baseUrl = (this.config.baseUrl as string) || process.env.AI_OMNIROUTE_URL || 'http://localhost:20128/v1';
    this.apiKey  = (this.config.apiKey  as string) || process.env.AI_OMNIROUTE_KEY  || 'omniroute';
    this.defaultModel = (this.config.model as string) || process.env.AI_OMNIROUTE_MODEL || 'auto';

    // Strip trailing slash
    this.baseUrl = this.baseUrl.replace(/\/$/, '');
  }

  protected getDefaultModels(): AIModel[] {
    return [
      {
        id: 'auto',
        name: 'Auto (OmniRoute selects best model)',
        maxTokens: 200000,
        supportsStreaming: true,
        supportsTools: true
      },
      {
        id: 'claude-3-5-sonnet-20241022',
        name: 'Claude 3.5 Sonnet',
        maxTokens: 200000,
        supportsStreaming: true,
        supportsTools: true
      },
      {
        id: 'claude-3-haiku-20240307',
        name: 'Claude 3 Haiku',
        maxTokens: 200000,
        supportsStreaming: true,
        supportsTools: true
      },
      {
        id: 'gpt-4o',
        name: 'GPT-4o',
        maxTokens: 128000,
        supportsStreaming: true,
        supportsTools: true
      },
      {
        id: 'gpt-4o-mini',
        name: 'GPT-4o Mini',
        maxTokens: 128000,
        supportsStreaming: true,
        supportsTools: true
      }
    ];
  }

  async complete(request: AIRequest): Promise<AIResponse> {
    const model = request.model || this.defaultModel;
    const messages = this.buildMessages(request);

    const body: Record<string, unknown> = {
      model,
      messages,
      temperature: request.temperature ?? 0.2,
      max_tokens: request.maxTokens ?? this.maxOutputTokens,
      stream: false,  // Explicitly disable SSE streaming — get plain JSON back
    };

    let response: Response;
    try {
      response = await fetch(this.chatUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`,
        },
        body: JSON.stringify(body),
      });
    } catch (err: any) {
      throw new Error(
        `${this.name} connection failed — ${this.connectionHint} ` +
        `Error: ${err?.message || err}`
      );
    }

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`${this.name} API error (${response.status}): ${text}`);
    }

    // Guard against SSE stream being returned despite stream:false
    const contentType = response.headers.get('content-type') || '';
    if (contentType.includes('text/event-stream')) {
      // Parse the first SSE data line as JSON
      const rawText = await response.text();
      const firstDataLine = rawText.split('\n').find(l => l.startsWith('data: ') && !l.includes('[DONE]'));
      if (!firstDataLine) throw new Error(`${this.name} returned an empty SSE stream`);
      const jsonStr = firstDataLine.slice('data: '.length).trim();
      const sseData = JSON.parse(jsonStr) as Record<string, unknown>;
      const content = this.extractContent(sseData);
      if (!content) throw new Error(`Could not extract content from ${this.name} SSE response: ${jsonStr.slice(0, 200)}`);
      return this.createResponse(content, model);
    }

    const data = await response.json() as Record<string, unknown>;

    // OpenAI-compatible response format
    const content = this.extractContent(data);
    if (!content) {
      throw new Error(`Unexpected ${this.name} response format: ${JSON.stringify(data).slice(0, 300)}`);
    }

    const usageRaw = data.usage as Record<string, number> | undefined;

    return this.createResponse(content, model, undefined, usageRaw ? {
      promptTokens: usageRaw.prompt_tokens ?? 0,
      completionTokens: usageRaw.completion_tokens ?? 0,
      totalTokens: usageRaw.total_tokens ?? 0,
    } : undefined);
  }


  async stream(request: AIRequest, onChunk: (chunk: string) => void): Promise<AIResponse> {
    // Fallback: use complete() and deliver as single chunk
    const response = await this.complete(request);
    onChunk(response.content);
    return response;
  }

  private extractContent(data: Record<string, unknown>): string {
    // Standard OpenAI / OmniRoute format
    if (Array.isArray(data.choices) && data.choices.length > 0) {
      const choice = data.choices[0] as Record<string, unknown>;
      const msg = choice.message as Record<string, unknown> | undefined;
      if (msg && typeof msg.content === 'string') return msg.content;
      if (typeof choice.text === 'string') return choice.text;
    }
    // Direct response field (Apps Script wrapper compat)
    if (typeof data.response === 'string') return data.response;
    // Anthropic-compatible format (in case OmniRoute proxies Anthropic)
    if (Array.isArray(data.content)) {
      const block = (data.content as Record<string, unknown>[]).find(b => b.type === 'text');
      if (block && typeof block.text === 'string') return block.text;
    }
    return '';
  }

  // ─── Structured helpers (mirror of AppsScriptProvider) ────────────────────

  async fixDockerfile(dockerfile: string, issues: any[], options?: any): Promise<DockerfileFixResponse> {
    const systemPrompt = `You are an expert Dockerfile security and best practices analyzer.
Analyze the provided Dockerfile and return a structured JSON response with:
1. fixedDockerfile - the corrected Dockerfile
2. issues - array of issues found (id, type, severity, line, message, rule, fixable, suggestion)
3. changes - array of changes made (type, originalLine, fixedLine, originalContent, fixedContent, description)
4. securityImprovements - array of security improvements made
5. explanation - human-readable explanation of all fixes

Types: syntax, security, best_practice, performance, style
Severities: critical, high, medium, low, info
Return ONLY valid JSON.`;

    const userPrompt = `Dockerfile to analyze and fix:\n\`\`\`dockerfile\n${dockerfile}\n\`\`\`\n\n${
      issues.length > 0 ? `Pre-detected issues: ${JSON.stringify(issues, null, 2)}` : ''
    }\n\nOptions: ${JSON.stringify(options || {})}`;

    const response = await this.complete({ prompt: userPrompt, systemPrompt, temperature: 0.1, maxTokens: this.maxOutputTokens });
    const structured = this.parseStructuredResponse<DockerfileFixResponse>(response.content, { parse: (d: any) => d });
    return structured || { fixedDockerfile: dockerfile, issues: [], changes: [], securityImprovements: [], explanation: 'AI response could not be parsed' };
  }

  async fixKubernetes(yaml: string, issues: any[], options?: any): Promise<KubernetesFixResponse> {
    const systemPrompt = `You are an expert Kubernetes YAML analyzer. Return structured JSON with:
fixedYaml, issues (id,resource,type,severity,path,message,rule,fixable,suggestion), changes, explanation.
Return ONLY valid JSON.`;
    const response = await this.complete({
      prompt: `YAML:\n\`\`\`yaml\n${yaml}\n\`\`\`\nIssues: ${JSON.stringify(issues)}\nOptions: ${JSON.stringify(options || {})}`,
      systemPrompt, temperature: 0.1, maxTokens: this.maxOutputTokens
    });
    const structured = this.parseStructuredResponse<KubernetesFixResponse>(response.content, { parse: (d: any) => d });
    return structured || { fixedYaml: yaml, issues: [], changes: [], explanation: 'Could not parse AI response' };
  }

  async fixJenkinsfile(jenkinsfile: string, issues: any[], options?: any): Promise<JenkinsfileFixResponse> {
    const systemPrompt = `You are an expert Jenkins pipeline analyzer. Return structured JSON with:
fixedJenkinsfile, issues (id,type,severity,line,message,rule,fixable,suggestion), changes, explanation.
Return ONLY valid JSON.`;
    const response = await this.complete({
      prompt: `Jenkinsfile:\n\`\`\`groovy\n${jenkinsfile}\n\`\`\`\nIssues: ${JSON.stringify(issues)}\nOptions: ${JSON.stringify(options || {})}`,
      systemPrompt, temperature: 0.1, maxTokens: this.maxOutputTokens
    });
    const structured = this.parseStructuredResponse<JenkinsfileFixResponse>(response.content, { parse: (d: any) => d });
    return structured || { fixedJenkinsfile: jenkinsfile, issues: [], changes: [], explanation: 'Could not parse AI response' };
  }

  async investigateLogs(question: string, logEntries: any[], context?: any): Promise<LogInvestigationResponse> {
    const systemPrompt = `You are an expert log analyst. Return structured JSON with:
rootCause, evidence, timeline, affectedServices, errorPatterns, recommendedActions, confidence (0-100), analyzedEntries.
Return ONLY valid JSON.`;
    const limited = logEntries.slice(0, 100);
    const response = await this.complete({
      prompt: `Question: ${question}\n\nLogs (${limited.length}):\n${JSON.stringify(limited, null, 2)}\n\nContext: ${JSON.stringify(context || {})}`,
      systemPrompt, temperature: 0.1, maxTokens: this.maxOutputTokens
    });
    const structured = this.parseStructuredResponse<LogInvestigationResponse>(response.content, { parse: (d: any) => d });
    return structured || { rootCause: 'Could not analyze logs', evidence: [], timeline: [], affectedServices: [], errorPatterns: [], recommendedActions: ['Check logs manually'], confidence: 0, analyzedEntries: 0 };
  }

  async fixDependency(pkg: string, currentVersion: string, targetVersion: string, vulnerabilities: any[], manifestContent: string): Promise<DependencyFixResponse> {
    const systemPrompt = `You are an expert dependency security analyst. Return structured JSON with:
explanation, targetVersion, breakingChanges (bool), filesToChange, upgradePath, confidence (0-100).
Return ONLY valid JSON.`;
    const response = await this.complete({
      prompt: `Package: ${pkg}\nCurrent: ${currentVersion}\nTarget: ${targetVersion}\nVulns: ${JSON.stringify(vulnerabilities)}\nManifest:\n${manifestContent}`,
      systemPrompt, temperature: 0.1, maxTokens: this.maxOutputTokens
    });
    const structured = this.parseStructuredResponse<DependencyFixResponse>(response.content, { parse: (d: any) => d });
    return structured || { explanation: 'Could not analyze', targetVersion, breakingChanges: false, filesToChange: [], upgradePath: [], confidence: 0 };
  }

  async fixGitHubCode(finding: any, fileContent: string, surroundingContext: string): Promise<GitHubCodeFixResponse> {
    const systemPrompt = `You are an expert secure code reviewer. Return structured JSON with:
patch (unified diff), explanation, confidence (0-100), breakingChanges (array).
Return ONLY valid JSON.`;
    const response = await this.complete({
      prompt: `Finding: ${JSON.stringify(finding)}\n\nFile:\n${fileContent}\n\nContext:\n${surroundingContext}`,
      systemPrompt, temperature: 0.1, maxTokens: this.maxOutputTokens
    });
    const structured = this.parseStructuredResponse<GitHubCodeFixResponse>(response.content, { parse: (d: any) => d });
    return structured || { patch: '', explanation: 'Could not generate fix', confidence: 0, breakingChanges: [] };
  }
}
