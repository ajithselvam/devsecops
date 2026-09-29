import { BaseAIProvider } from '../base';
import { AIRequest, AIResponse, AIModel, DockerfileFixResponse, KubernetesFixResponse, JenkinsfileFixResponse, LogInvestigationResponse, DependencyFixResponse, GitHubCodeFixResponse } from '../types';
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
export declare class OmniRouteProvider extends BaseAIProvider {
    name: string;
    type: string;
    protected baseUrl: string;
    protected apiKey: string;
    protected defaultModel: string;
    /** Cap used when a caller does not request a specific size. */
    protected maxOutputTokens: number;
    /** Extra context appended to connection errors. */
    protected get connectionHint(): string;
    /** Absolute chat-completions URL for this provider. */
    protected get chatUrl(): string;
    protected onInitialize(): Promise<void>;
    protected getDefaultModels(): AIModel[];
    complete(request: AIRequest): Promise<AIResponse>;
    stream(request: AIRequest, onChunk: (chunk: string) => void): Promise<AIResponse>;
    private extractContent;
    fixDockerfile(dockerfile: string, issues: any[], options?: any): Promise<DockerfileFixResponse>;
    fixKubernetes(yaml: string, issues: any[], options?: any): Promise<KubernetesFixResponse>;
    fixJenkinsfile(jenkinsfile: string, issues: any[], options?: any): Promise<JenkinsfileFixResponse>;
    investigateLogs(question: string, logEntries: any[], context?: any): Promise<LogInvestigationResponse>;
    fixDependency(pkg: string, currentVersion: string, targetVersion: string, vulnerabilities: any[], manifestContent: string): Promise<DependencyFixResponse>;
    fixGitHubCode(finding: any, fileContent: string, surroundingContext: string): Promise<GitHubCodeFixResponse>;
}
//# sourceMappingURL=omniroute.d.ts.map