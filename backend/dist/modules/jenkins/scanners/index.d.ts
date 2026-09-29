import { Job } from 'bullmq';
export interface JenkinsfileScanResult {
    summary: {
        totalFindings: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
    };
    findings: JenkinsfileFinding[];
}
export interface JenkinsfileFinding {
    id: string;
    type: 'security' | 'best-practice' | 'performance' | 'reliability' | 'maintainability' | 'secret';
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    title: string;
    description: string;
    file: string;
    line: number;
    column?: number;
    ruleId?: string;
    cwe?: string;
    references?: string[];
    fixable?: boolean;
}
export interface ScanProgress {
    progress: number;
    currentStep: string;
}
export declare function scanJenkinsfile(jenkinsfile: string, job: Job, scanId: string): Promise<JenkinsfileScanResult>;
export declare function fixJenkinsfile(jenkinsfile: string, findings: JenkinsfileFinding[], job: Job): Promise<{
    fixedJenkinsfile: string;
    changes: any[];
}>;
export declare function generateJenkinsfile(spec: any, job: Job): Promise<{
    jenkinsfile: string;
}>;
//# sourceMappingURL=index.d.ts.map