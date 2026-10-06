import { BaseAIProvider } from '../base';
import { AIRequest, AIResponse, AIModel, DockerfileFixResponse, KubernetesFixResponse, JenkinsfileFixResponse, LogInvestigationResponse, DependencyFixResponse, GitHubCodeFixResponse } from '../types';
import { AIProviderConfig } from '@devsecops/shared/types';

/** Request shape understood by the Apps Script bridge (doPost and doGet). */
interface AppsScriptPayload {
  prompt: string;
  systemPrompt: string;
  context: string;
  model: string;
  temperature: number;
  maxTokens: number;
}

export class AppsScriptProvider extends BaseAIProvider {
  name = 'Google Apps Script (OpenRouter Bridge)';
  type = 'apps_script';
  private endpoint: string = '';
  private apiKey: string = '';

  /** OpenRouter's auto-router: always resolves to a currently available free model. */
  private static readonly AUTO_ROUTER_MODEL = 'openrouter/free';

  /**
   * Most free OpenRouter models are reasoning models, and they spend the whole
   * token budget on hidden reasoning — below ~200 tokens OpenRouter returns an
   * empty message and the bridge answers "No response generated". Give every call
   * enough room to actually say something.
   */
  private static readonly MIN_MAX_TOKENS = 1024;

  /**
   * Apps Script web apps only expose a GET query-parameter interface (see
   * requestViaGet), so every field travels in the URL. Google rejects these
   * around 12KB, so stay well under that.
   */
  private static readonly MAX_URL_LENGTH = 10000;

  /** Free models are slow; the bridge is a cold start on top of that. */
  private timeoutMs = 180000;

  /** undefined = not probed yet, true = POST works, false = GET only. */
  private postSupported?: boolean;

  /**
   * Model id → epoch ms before which it is skipped. OpenRouter rate limits free
   * models per account, so a model that just failed usually keeps failing for the
   * rest of a scan; without this every call would re-probe the dead model first.
   */
  private modelCooldowns: Map<string, number> = new Map();
  private static readonly MODEL_COOLDOWN_MS = 300000;

  /**
   * OpenRouter meters every ":free" model id against a single shared daily quota,
   * so one 429 on a free model means the rest are spent too. This timestamp
   * parks all free models at once instead of re-probing each one per request.
   */
  private freeQuotaCooldownUntil = 0;
  private static readonly FREE_QUOTA_COOLDOWN_MS = 900000;

  private static isFreeModel(id: string): boolean {
    return id.endsWith(':free') || id === AppsScriptProvider.AUTO_ROUTER_MODEL;
  }

  protected async onInitialize(): Promise<void> {
    this.endpoint = (this.config.endpoint as string) || process.env.AI_APPS_SCRIPT_URL || '';
    this.endpoint = this.endpoint.trim();
    this.apiKey = (this.config.apiKey as string) || '';
    const timeout = parseInt(
      (this.config.timeoutMs as string) || process.env.AI_APPS_SCRIPT_TIMEOUT_MS || '',
      10
    );
    if (Number.isFinite(timeout) && timeout > 0) {
      this.timeoutMs = timeout;
    }
    if (!this.endpoint) {
      throw new Error('Apps Script endpoint not configured');
    }
  }

  protected getDefaultModels(): AIModel[] {
    // Order matters: complete() walks this list as a fallback chain, so the
    // strongest model that is currently reachable is first. OpenRouter retires
    // free model ids without warning, which is why every entry has a successor.
    return [
      {
        id: 'nvidia/nemotron-3-super-120b-a12b:free',
        name: 'NVIDIA Nemotron 3 Super 120B (Free)',
        maxTokens: 8192,
        supportsStreaming: false,
        supportsTools: false
      },
      {
        id: 'poolside/laguna-s-2.1:free',
        name: 'Poolside Laguna S 2.1 Code (Free)',
        maxTokens: 8192,
        supportsStreaming: false,
        supportsTools: false
      },
      {
        // Not a ":free" id, so it is metered separately and stays available after
        // the shared free quota is spent. Weaker, but it is the safety net.
        id: 'meta-llama/llama-3.2-3b-instruct',
        name: 'Llama 3.2 3B Instruct',
        maxTokens: 8192,
        supportsStreaming: false,
        supportsTools: false
      },
      {
        id: 'nvidia/nemotron-3.5-lightning:free',
        name: 'NVIDIA Nemotron 3.5 Lightning (Free)',
        maxTokens: 8192,
        supportsStreaming: false,
        supportsTools: false
      },
      {
        id: 'qwen/qwen3.8-27b:free',
        name: 'Qwen 3.8 27B (Free)',
        maxTokens: 8192,
        supportsStreaming: false,
        supportsTools: false
      },
      {
        // Last resort: the auto-router. It is broad but picks at random, so it can
        // land on something unsuitable (e.g. a content-safety model) — hence last.
        id: AppsScriptProvider.AUTO_ROUTER_MODEL,
        name: 'Auto (Best Available Free Model)',
        maxTokens: 8192,
        supportsStreaming: false,
        supportsTools: false
      }
    ];
  }

  async complete(request: AIRequest): Promise<AIResponse> {
    const defaultModel = this.getModels()[0]?.id || AppsScriptProvider.AUTO_ROUTER_MODEL;
    const model = request.model || defaultModel;
    const systemPrompt = request.systemPrompt || '';
    const additionalContext =
      request.context && typeof request.context.additional === 'string'
        ? request.context.additional
        : '';

    const maxTokens = Math.max(request.maxTokens ?? 8192, AppsScriptProvider.MIN_MAX_TOKENS);
    const payload = {
      prompt: request.prompt,
      systemPrompt,
      context: additionalContext,
      model,
      temperature: request.temperature ?? 0.2,
      maxTokens
    };

    // Free OpenRouter models get retired, paywalled or rate limited without
    // notice, so a failure means "try the next one" rather than "fail the scan".
    // Models in a failure cooldown are skipped, as are free models while the
    // shared OpenRouter free quota is spent.
    const now = Date.now();
    const modelChain = this.buildModelChain(model);
    const cooldownUntil = (id: string): number =>
      Math.max(
        this.modelCooldowns.get(id) ?? 0,
        AppsScriptProvider.isFreeModel(id) ? this.freeQuotaCooldownUntil : 0
      );

    const usable = modelChain.filter(id => cooldownUntil(id) <= now);
    // Never lock the provider out: if everything is cooling down — a transient
    // outage hitting all models at once — still probe whichever recovers first.
    const chain =
      usable.length > 0
        ? usable
        : [modelChain.reduce((best, id) => (cooldownUntil(id) < cooldownUntil(best) ? id : best))];

    const failures: string[] = [];
    for (const candidate of chain) {
      // Re-check per iteration: parking the free quota part-way through the walk
      // should skip the remaining free models, not abandon the whole chain —
      // a non-free fallback further down is still worth trying.
      if (failures.length > 0 && cooldownUntil(candidate) > now) continue;
      try {
        return await this.dispatch({ ...payload, model: candidate });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        if (AppsScriptProvider.isFreeModel(candidate) && /API error \(429\)/.test(message)) {
          this.freeQuotaCooldownUntil = Date.now() + AppsScriptProvider.FREE_QUOTA_COOLDOWN_MS;
          console.warn(
            '[AI] OpenRouter free-model quota is spent — parking all ":free" models for ' +
            `${AppsScriptProvider.FREE_QUOTA_COOLDOWN_MS / 60000} minutes.`
          );
        }
        this.modelCooldowns.set(candidate, Date.now() + AppsScriptProvider.MODEL_COOLDOWN_MS);
        console.warn(`[AI] Apps Script model '${candidate}' failed: ${message.slice(0, 200)}`);
        failures.push(`${candidate}: ${message.slice(0, 200)}`);
      }
    }

    // OpenRouter meters every ":free" model id against one shared daily quota, so
    // an all-429 outcome is a quota problem, not a bad model list — say so instead
    // of returning six identical-looking failures.
    if (failures.length && failures.every(f => /API error \(429\)/.test(f))) {
      throw new Error(
        'OpenRouter free-model daily quota is exhausted (all ":free" models share one quota). ' +
        'Add credits at https://openrouter.ai/credits to raise the limit, or wait for the daily reset.'
      );
    }

    throw new Error(`AI request failed: ${failures.join(' ; ')}`);
  }

  /**
   * The requested model first, then the other configured models in preference
   * order, then the auto-router. An explicit request.model that is already in the
   * list is not repeated.
   */
  private buildModelChain(requested: string): string[] {
    const configured = this.getModels().map(m => m.id);
    const chain = [requested, ...configured, AppsScriptProvider.AUTO_ROUTER_MODEL];
    return chain.filter((id, index) => chain.indexOf(id) === index);
  }

  /**
   * Runs the request over both transports Apps Script can expose and returns the
   * first real AI answer.
   *
   * A web app answers every request with a 302 to script.googleusercontent.com.
   * Per RFC 7231 a 302 after a POST is replayed as a GET, which drops the request
   * body — so a plain `fetch(..., { redirect: 'follow' })` reaches doGet() with no
   * parameters and gets a health-check payload back instead of AI output. We first
   * replay the POST across the redirect by hand to keep the body, and fall back to
   * the query-parameter route when the deployment rejects that.
   */
  private async dispatch(payload: AppsScriptPayload): Promise<AIResponse> {
    const failures: string[] = [];
    const transports: Array<() => Promise<Record<string, unknown>>> = [];

    if (this.postSupported !== false) {
      transports.push(() => this.requestViaPost(payload));
    }
    transports.push(() => this.requestViaGet(payload));

    for (const transport of transports) {
      try {
        const data = await transport();
        const content = this.extractContent(data);
        return this.createResponse(content, payload.model, undefined, {
          promptTokens: this.estimateTokens(payload.prompt),
          completionTokens: this.estimateTokens(content),
          totalTokens: this.estimateTokens(payload.prompt) + this.estimateTokens(content)
        });
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        // Deployments that reject the echoed POST will reject every one of them,
        // so stop paying for the probe after the first refusal.
        if (this.postSupported === undefined && /POST .* failed: 40[1359]/.test(message)) {
          this.postSupported = false;
          console.warn(
            '[AI] Apps Script deployment rejects POST bodies — using the GET query-parameter route from now on.'
          );
        }
        failures.push(message);
      }
    }
    throw new Error(failures.join(' ; '));
  }

  private buildHeaders(): Record<string, string> {
    return this.apiKey ? { Authorization: `Bearer ${this.apiKey}` } : {};
  }

  private async request(url: string, init: RequestInit): Promise<Response> {
    return fetch(url, { ...init, signal: AbortSignal.timeout(this.timeoutMs) });
  }

  private async requestViaPost(payload: AppsScriptPayload): Promise<Record<string, unknown>> {
    const body = JSON.stringify(payload);
    const headers = { 'Content-Type': 'application/json', ...this.buildHeaders() };
    let url = this.endpoint;

    for (let hop = 0; hop < 4; hop++) {
      const response = await this.request(url, { method: 'POST', headers, body, redirect: 'manual' });
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (!location) {
          throw new Error(`POST ${this.endpoint} returned ${response.status} without a Location header`);
        }
        url = new URL(location, url).toString();
        continue;
      }
      if (!response.ok) {
        throw new Error(`POST ${this.endpoint} failed: ${response.status} ${(await response.text()).slice(0, 200)}`);
      }
      return this.readJson(await response.text());
    }
    throw new Error(`POST ${this.endpoint} exceeded the redirect limit`);
  }

  private async requestViaGet(payload: AppsScriptPayload): Promise<Record<string, unknown>> {
    const url = this.buildQueryUrl(payload);
    const response = await this.request(url, {
      method: 'GET',
      headers: this.buildHeaders(),
      redirect: 'follow'
    });
    if (!response.ok) {
      throw new Error(`GET ${this.endpoint} failed: ${response.status} ${(await response.text()).slice(0, 200)}`);
    }
    return this.readJson(await response.text());
  }

  private buildQueryUrl(payload: AppsScriptPayload): string {
    const build = (context: string): string => {
      const params = new URLSearchParams();
      params.set('prompt', payload.prompt);
      if (payload.systemPrompt) params.set('systemPrompt', payload.systemPrompt);
      if (context) params.set('context', context);
      params.set('model', payload.model);
      params.set('temperature', String(payload.temperature));
      params.set('maxTokens', String(payload.maxTokens));
      return `${this.endpoint}?${params.toString()}`;
    };

    let url = build(payload.context);
    if (url.length <= AppsScriptProvider.MAX_URL_LENGTH) {
      return url;
    }

    // The core prompt and system prompt are not negotiable, so shed the optional
    // context first and only then report the request as undeliverable.
    if (payload.context) {
      const keep = Math.floor(payload.context.length / 2);
      url = build(`${payload.context.slice(0, keep)}\n[... context truncated to fit the Apps Script URL limit ...]`);
      if (url.length <= AppsScriptProvider.MAX_URL_LENGTH) {
        console.warn(
          `[AI] Apps Script GET URL limit: context truncated from ${payload.context.length} to ${keep} chars`
        );
        return url;
      }
    }

    throw new Error(
      `request is too large for the Apps Script GET bridge (${url.length} > ${AppsScriptProvider.MAX_URL_LENGTH} chars). ` +
      'Shrink the input, or configure a provider that accepts POST bodies (freeai / omniroute / openrouter).'
    );
  }

  private async readJson(text: string): Promise<Record<string, unknown>> {
    try {
      const data = JSON.parse(text) as unknown;
      if (!data || typeof data !== 'object' || Array.isArray(data)) {
        throw new Error('not a JSON object');
      }
      return data as Record<string, unknown>;
    } catch {
      throw new Error(`Apps Script returned a non-JSON body: ${text.trim().slice(0, 160)}`);
    }
  }

  private extractContent(data: Record<string, unknown>): string {
    // doGet() with no parameters answers with the bridge health check. Reaching it
    // means the prompt was lost somewhere in the redirect chain.
    if (
      data.status === 'ok' &&
      typeof data.service === 'string' &&
      typeof data.timestamp === 'string' &&
      typeof data.response === 'undefined'
    ) {
      throw new Error(
        'Apps Script returned a health-check response instead of AI output — the prompt was lost in the ' +
        'script.google.com redirect. Check that the deployment is a web app ("Anyone" access) and that doGet accepts the prompt.'
      );
    }

    if (typeof data.error === 'string') {
      throw new Error(`Apps Script returned error: ${data.error}`);
    }

    if (typeof data.response === 'string' && data.response.trim()) {
      // The bridge's sentinel for "OpenRouter returned an empty message", which
      // happens when a reasoning model spends the whole token budget thinking.
      // Treating it as content would silently return nothing to the caller.
      if (data.response.trim() === 'No response generated') {
        throw new Error(
          'OpenRouter returned an empty message for this model (usually too small a max_tokens budget)'
        );
      }
      return data.response;
    }

    // OpenAI/OpenRouter-shaped payloads, in case the bridge is swapped for a raw endpoint.
    if (Array.isArray(data.choices) && data.choices.length > 0) {
      const choice = data.choices[0] as Record<string, unknown>;
      const message = choice.message as Record<string, unknown> | undefined;
      if (message && typeof message.content === 'string' && message.content) {
        return message.content;
      }
      if (typeof choice.text === 'string' && choice.text) {
        return choice.text;
      }
    }

    if (typeof data.content === 'string' && data.content) {
      return data.content;
    }

    throw new Error(`Unexpected AI response format. Got: ${JSON.stringify(data).slice(0, 200)}`);
  }

  async stream(request: AIRequest, onChunk: (chunk: string) => void): Promise<AIResponse> {
    // Apps Script doesn't support streaming, fall back to complete
    const response = await this.complete(request);
    onChunk(response.content);
    return response;
  }

  // Structured responses for specific tasks
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

    const userPrompt = `Dockerfile to analyze and fix:
\`\`\`dockerfile
${dockerfile}
\`\`\`

${issues.length > 0 ? `Pre-detected issues: ${JSON.stringify(issues, null, 2)}` : ''}

Options: ${JSON.stringify(options || {})}`;

    const response = await this.complete({
      prompt: userPrompt,
      systemPrompt,
      temperature: 0.1,
      maxTokens: 16384
    });

    const structured = this.parseStructuredResponse<DockerfileFixResponse>(response.content, {
      parse: (data: any) => data // We'll validate manually
    });

    if (structured) return structured;

    // Fallback: return minimal response
    return {
      fixedDockerfile: dockerfile,
      issues: [],
      changes: [],
      securityImprovements: [],
      explanation: 'AI response could not be parsed as structured data'
    };
  }

  async fixKubernetes(yaml: string, issues: any[], options?: any): Promise<KubernetesFixResponse> {
    const systemPrompt = `You are an expert Kubernetes YAML analyzer and fixer.
Analyze the provided YAML and return structured JSON with:
1. fixedYaml - corrected YAML
2. issues - array of issues (id, resource, type, severity, path, message, rule, fixable, suggestion)
3. changes - array of changes (type, originalLine, fixedLine, originalContent, fixedContent, description)
4. explanation - human-readable explanation

Types: schema, security, best_practice, performance, reliability
Severities: critical, high, medium, low, info
Return ONLY valid JSON.`;

    const response = await this.complete({
      prompt: `YAML to analyze and fix:\n\`\`\`yaml\n${yaml}\n\`\`\`\n\nIssues: ${JSON.stringify(issues)}\nOptions: ${JSON.stringify(options || {})}`,
      systemPrompt,
      temperature: 0.1,
      maxTokens: 16384
    });

    const structured = this.parseStructuredResponse<KubernetesFixResponse>(response.content, { parse: (d: any) => d });
    return structured || { fixedYaml: yaml, issues: [], changes: [], explanation: 'Could not parse AI response' };
  }

  async fixJenkinsfile(jenkinsfile: string, issues: any[], options?: any): Promise<JenkinsfileFixResponse> {
    const systemPrompt = `You are an expert Jenkins pipeline analyzer.
Analyze the Jenkinsfile and return structured JSON with:
1. fixedJenkinsfile - corrected Jenkinsfile
2. issues - array of issues (id, type, severity, line, message, rule, fixable, suggestion)
3. changes - array of changes
4. explanation - human-readable explanation

Types: syntax, security, best_practice, performance, reliability
Severities: critical, high, medium, low, info
Return ONLY valid JSON.`;

    const response = await this.complete({
      prompt: `Jenkinsfile to analyze and fix:\n\`\`\`groovy\n${jenkinsfile}\n\`\`\`\n\nIssues: ${JSON.stringify(issues)}\nOptions: ${JSON.stringify(options || {})}`,
      systemPrompt,
      temperature: 0.1,
      maxTokens: 16384
    });

    const structured = this.parseStructuredResponse<JenkinsfileFixResponse>(response.content, { parse: (d: any) => d });
    return structured || { fixedJenkinsfile: jenkinsfile, issues: [], changes: [], explanation: 'Could not parse AI response' };
  }

  async investigateLogs(question: string, logEntries: any[], context?: any): Promise<LogInvestigationResponse> {
    const systemPrompt = `You are an expert log analyst and incident investigator.
Analyze the provided logs and answer the question with structured JSON:
1. rootCause - the root cause of the issue
2. evidence - array of relevant log entries with relevance score and explanation
3. timeline - array of timeline events
4. affectedServices - array of affected service names
5. errorPatterns - array of error patterns found
6. recommendedActions - array of recommended actions
7. confidence - confidence score 0-100
8. analyzedEntries - number of entries analyzed

Return ONLY valid JSON.`;

    // Limit log entries to avoid token limits
    const limitedEntries = logEntries.slice(0, 100);

    const response = await this.complete({
      prompt: `Question: ${question}\n\nLog entries (${limitedEntries.length} of ${logEntries.length}):\n${JSON.stringify(limitedEntries, null, 2)}\n\nContext: ${JSON.stringify(context || {})}`,
      systemPrompt,
      temperature: 0.1,
      maxTokens: 16384
    });

    const structured = this.parseStructuredResponse<LogInvestigationResponse>(response.content, { parse: (d: any) => d });
    return structured || {
      rootCause: 'Could not analyze logs',
      evidence: [],
      timeline: [],
      affectedServices: [],
      errorPatterns: [],
      recommendedActions: ['Check logs manually'],
      confidence: 0,
      analyzedEntries: 0
    };
  }

  async fixDependency(pkg: string, currentVersion: string, targetVersion: string, vulnerabilities: any[], manifestContent: string): Promise<DependencyFixResponse> {
    const systemPrompt = `You are an expert dependency security analyst.
Analyze the vulnerability and provide a structured fix recommendation:
1. explanation - why this is vulnerable and how the fix works
2. targetVersion - recommended version
3. breakingChanges - whether update may break things
4. filesToChange - list of files that need modification
5. upgradePath - step-by-step upgrade instructions
6. confidence - confidence score 0-100

Return ONLY valid JSON.`;

    const response = await this.complete({
      prompt: `Package: ${pkg}\nCurrent: ${currentVersion}\nTarget: ${targetVersion}\nVulnerabilities: ${JSON.stringify(vulnerabilities)}\nManifest:\n${manifestContent}`,
      systemPrompt,
      temperature: 0.1,
      maxTokens: 8192
    });

    const structured = this.parseStructuredResponse<DependencyFixResponse>(response.content, { parse: (d: any) => d });
    return structured || {
      explanation: 'Could not analyze',
      targetVersion,
      breakingChanges: false,
      filesToChange: [],
      upgradePath: [],
      confidence: 0
    };
  }

  async fixGitHubCode(finding: any, fileContent: string, surroundingContext: string): Promise<GitHubCodeFixResponse> {
    const systemPrompt = `You are an expert secure code reviewer.
Generate a safe patch for the security finding:
1. patch - unified diff format patch
2. explanation - what the fix does
3. confidence - confidence score 0-100
4. breakingChanges - potential breaking changes

Return ONLY valid JSON.`;

    const response = await this.complete({
      prompt: `Finding: ${JSON.stringify(finding)}\n\nFile content:\n${fileContent}\n\nSurrounding context:\n${surroundingContext}`,
      systemPrompt,
      temperature: 0.1,
      maxTokens: 8192
    });

    const structured = this.parseStructuredResponse<GitHubCodeFixResponse>(response.content, { parse: (d: any) => d });
    return structured || {
      patch: '',
      explanation: 'Could not generate fix',
      confidence: 0,
      breakingChanges: []
    };
  }

  private estimateTokens(text: string): number {
    // Rough estimation: ~4 chars per token
    return Math.ceil(text.length / 4);
  }
}