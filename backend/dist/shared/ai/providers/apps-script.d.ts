import { BaseAIProvider } from '../base';
import { AIRequest, AIResponse, AIModel, DockerfileFixResponse, KubernetesFixResponse, JenkinsfileFixResponse, LogInvestigationResponse, DependencyFixResponse, GitHubCodeFixResponse } from '../types';
export declare class AppsScriptProvider extends BaseAIProvider {
    name: string;
    type: string;
    private endpoint;
    private apiKey;
    protected onInitialize(): Promise<void>;
    protected getDefaultModels(): AIModel[];
    complete(request: AIRequest): Promise<AIResponse>;
    stream(request: AIRequest, onChunk: (chunk: string) => void): Promise<AIResponse>;
    fixDockerfile(dockerfile: string, issues: any[], options?: any): Promise<DockerfileFixResponse>;
    fixKubernetes(yaml: string, issues: any[], options?: any): Promise<KubernetesFixResponse>;
    fixJenkinsfile(jenkinsfile: string, issues: any[], options?: any): Promise<JenkinsfileFixResponse>;
    investigateLogs(question: string, logEntries: any[], context?: any): Promise<LogInvestigationResponse>;
    fixDependency(pkg: string, currentVersion: string, targetVersion: string, vulnerabilities: any[], manifestContent: string): Promise<DependencyFixResponse>;
    fixGitHubCode(finding: any, fileContent: string, surroundingContext: string): Promise<GitHubCodeFixResponse>;
    private estimateTokens;
}
//# sourceMappingURL=apps-script.d.ts.map