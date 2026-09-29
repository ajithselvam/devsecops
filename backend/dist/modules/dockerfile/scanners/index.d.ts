import { Job } from 'bullmq';
export interface DockerfileScanResult {
    summary: {
        totalFindings: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
    };
    findings: DockerfileFinding[];
    sbom?: any;
}
export interface DockerfileFinding {
    id: string;
    type: string;
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
    fixable?: boolean;
    fixedVersion?: string;
}
export interface ScanProgress {
    progress: number;
    currentStep: string;
}
export declare function scanDockerfile(dockerfile: string, job: Job, scanId: string): Promise<DockerfileScanResult>;
export declare function fixDockerfile(dockerfile: string, findings: DockerfileFinding[], job: Job): Promise<{
    fixedDockerfile: string;
    changes: any[];
}>;
export declare function scanDockerImage(imageName: string, job: Job, scanId: string): Promise<DockerfileScanResult>;
export declare function fixDockerImage(dockerfile: string, vulnerabilities: DockerfileFinding[], job: Job): Promise<{
    fixedDockerfile: string;
    beforeVulnerabilities: DockerfileFinding[];
    afterVulnerabilities: DockerfileFinding[];
}>;
//# sourceMappingURL=index.d.ts.map