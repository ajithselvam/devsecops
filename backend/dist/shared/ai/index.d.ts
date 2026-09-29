import { AIProvider, AIRequest, AIResponse, DockerfileFixResponse, KubernetesFixResponse, JenkinsfileFixResponse, LogInvestigationResponse, DependencyFixResponse, GitHubCodeFixResponse } from './types';
import { AIProviderConfig } from '@devsecops/shared/types';
export declare class AIService {
    private providers;
    private defaultProvider;
    private initialized;
    initialize(): Promise<void>;
    getProvider(type?: string): AIProvider;
    getAvailableProviders(): AIProviderConfig[];
    setDefaultProvider(type: string): void;
    complete(request: AIRequest, providerType?: string): Promise<AIResponse>;
    ask(data: {
        prompt: string;
        context?: string;
        model?: string;
        temperature?: number;
        maxTokens?: number;
        systemPrompt?: string;
    }): Promise<{
        response: string;
        model: string;
        usage: any;
    }>;
    stream(request: AIRequest, onChunk: (chunk: string) => void, providerType?: string): Promise<AIResponse>;
    fixDockerfile(dockerfile: string, issues: any[], options?: any): Promise<DockerfileFixResponse>;
    fixKubernetes(yaml: string, issues: any[], options?: any): Promise<KubernetesFixResponse>;
    fixJenkinsfile(jenkinsfile: string, issues: any[], options?: any): Promise<JenkinsfileFixResponse>;
    investigateLogs(question: string, logEntries: any[], context?: any): Promise<LogInvestigationResponse>;
    fixDependency(pkg: string, currentVersion: string, targetVersion: string, vulnerabilities: any[], manifestContent: string): Promise<DependencyFixResponse>;
    fixGitHubCode(finding: any, fileContent: string, surroundingContext: string): Promise<GitHubCodeFixResponse>;
    healthCheck(): Promise<Record<string, boolean>>;
}
export declare const aiService: AIService;
export declare function getAIProvider(): AIProvider;
//# sourceMappingURL=index.d.ts.map