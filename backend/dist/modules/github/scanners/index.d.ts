import { Job } from 'bullmq';
export interface GitHubScanResult {
    summary: {
        totalFindings: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
    };
    findings: GitHubFinding[];
}
export interface GitHubFinding {
    id: string;
    type: 'vulnerability' | 'misconfiguration' | 'secret' | 'code-quality' | 'dependency' | 'license' | 'sast' | 'iac';
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    title: string;
    description: string;
    file: string;
    line: number;
    column?: number;
    ruleId?: string;
    cwe?: string;
    cvss?: number;
    references?: string[];
    commit?: string;
    author?: string;
    fixable?: boolean;
    package?: string;
    installedVersion?: string;
    fixedVersion?: string;
    cve?: string;
    code?: string;
}
export interface ScanProgress {
    progress: number;
    currentStep: string;
}
export declare function persistGitHubFindings(scanId: string, findings: GitHubFinding[]): Promise<unknown>;
export declare function normalizeGitHubRepoUrl(raw: string): string;
export declare function scanGitHubRepo(repoUrl: string, branch: string, token: string, job: Job, scanId: string, scanTypes?: string[]): Promise<GitHubScanResult>;
export declare function fixGitHubCode(finding: GitHubFinding, fileContent: string, surroundingContext: string, job: Job): Promise<{
    fixedCode: string;
    explanation: string;
    confidence: number;
}>;
//# sourceMappingURL=index.d.ts.map