import { BaseAIProvider } from '../base';
import { AIRequest, AIResponse, AIModel, DockerfileFixResponse, KubernetesFixResponse, JenkinsfileFixResponse, LogInvestigationResponse, DependencyFixResponse, GitHubCodeFixResponse } from '../types';
import { AIProviderConfig } from '@devsecops/shared/types';

export class AppsScriptProvider extends BaseAIProvider {
  name = 'Google Apps Script (OpenRouter Bridge)';
  type = 'apps_script';
  private endpoint: string = '';
  private apiKey: string = '';

  protected async onInitialize(): Promise<void> {
    this.endpoint = this.config.endpoint as string || process.env.AI_APPS_SCRIPT_URL || '';
    this.apiKey = this.config.apiKey as string || '';
    if (!this.endpoint) {
      throw new Error('Apps Script endpoint not configured');
    }
  }

  protected getDefaultModels(): AIModel[] {
    return [
      {
        // openrouter/free is the official OpenRouter auto-router — always picks
        // a currently available free model, so it won't break when individual
        // free models get paywalled or removed.
        id: 'openrouter/free',
        name: 'Auto (Best Available Free Model)',
        maxTokens: 8192,
        supportsStreaming: false,
        supportsTools: false
      },
      {
        id: 'meta-llama/llama-3.2-3b-instruct',
        name: 'Llama 3.2 3B Instruct (OpenRouter)',
        maxTokens: 8192,
        supportsStreaming: false,
        supportsTools: false
      },
      {
        id: 'nvidia/llama-3.1-nemotron-ultra-253b:free',
        name: 'NVIDIA Nemotron Ultra (Free)',
        maxTokens: 8192,
        supportsStreaming: false,
        supportsTools: false
      },
      {
        id: 'liquid/lfm2.5-2.6b:free',
        name: 'Liquid LFM2.5 2.6B (Free)',
        maxTokens: 8192,
        supportsStreaming: false,
        supportsTools: false
      },
      {
        id: 'qwen/qwen-2.5-7b-instruct:free',
        name: 'Qwen 2.5 7B Instruct (Free)',
        maxTokens: 8192,
        supportsStreaming: false,
        supportsTools: false
      }
    ];
  }

  async complete(request: AIRequest): Promise<AIResponse> {
    // Use the first free model as default
    const defaultModel = this.getModels()[0]?.id || 'meta-llama/llama-3.2-3b-instruct:free';
    const model = request.model || defaultModel;
    const systemPrompt = request.systemPrompt || '';
    const fullPrompt = systemPrompt ? `${systemPrompt}\n\n${request.prompt}` : request.prompt;

    // Google Apps Script web apps redirect POST requests to script.googleusercontent.com.
    // The redirect is followed but the body is preserved only if we send the payload correctly.
    // We send both the JSON body and encode critical fields as query params as a fallback.
    const payload = {
      prompt: fullPrompt,
      model: model,
      temperature: request.temperature ?? 0.2,
      maxTokens: request.maxTokens ?? 8192,
      systemPrompt: systemPrompt,
      context: request.context
    };

    try {
      const response = await fetch(this.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(this.apiKey && { 'Authorization': `Bearer ${this.apiKey}` })
        },
        body: JSON.stringify(payload),
        redirect: 'follow'
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Apps Script error: ${response.status} ${errorText}`);
      }

      const data = await response.json() as Record<string, unknown>;

      // Detect health-check / status-only response — this happens when Google Apps Script
      // redirects the POST to a GET (stripping the body), and the doGet handler returns
      // {status:'ok', service:'...', model:'...', timestamp:'...'} instead of actual AI output.
      if (
        data.status === 'ok' &&
        typeof data.service === 'string' &&
        typeof data.timestamp === 'string' &&
        typeof data.response === 'undefined'
      ) {
        throw new Error(
          'Apps Script returned a health-check response instead of AI output. ' +
          'This usually means the POST body was lost during redirect (Google Apps Script limitation). ' +
          'Please ensure your Apps Script doPost handler is deployed correctly and the endpoint URL is the exec URL (not the dev URL).'
        );
      }

      // Detect error response from Apps Script
      if (typeof data.error === 'string') {
        throw new Error(`Apps Script returned error: ${data.error}`);
      }

      // The Apps Script returns: { response: "...", model: "...", usage: {...} }
      // Or OpenAI-compatible format: { choices: [{ message: { content: "..." } }] }
      let content = '';
      if (typeof data.response === 'string') {
        // Apps Script wrapper format — primary expected format
        content = data.response;
      } else if (Array.isArray(data.choices) && data.choices.length > 0) {
        // OpenAI/OpenRouter format
        const choice = data.choices[0] as Record<string, unknown>;
        if (choice.message && typeof choice.message === 'object' && choice.message !== null) {
          const message = choice.message as Record<string, unknown>;
          if (typeof message.content === 'string') {
            content = message.content;
          }
        } else if (typeof choice.text === 'string') {
          content = choice.text;
        }
      }

      if (!content) {
        throw new Error(
          `Unexpected AI response format. Got: ${JSON.stringify(data).slice(0, 200)}`
        );
      }

      return this.createResponse(content, model, undefined, {
        promptTokens: this.estimateTokens(fullPrompt),
        completionTokens: this.estimateTokens(content),
        totalTokens: this.estimateTokens(fullPrompt) + this.estimateTokens(content)
      });
    } catch (error) {
      console.error('Apps Script AI error:', error);
      throw new Error(`AI request failed: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
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