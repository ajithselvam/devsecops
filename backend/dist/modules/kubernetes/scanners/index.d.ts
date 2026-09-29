import { Job } from 'bullmq';
export interface KubernetesScanResult {
    summary: {
        totalFindings: number;
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
    };
    findings: KubernetesFinding[];
}
export interface KubernetesFinding {
    id: string;
    type: 'vulnerability' | 'misconfiguration' | 'secret' | 'rbac' | 'network' | 'best-practice';
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
    namespace?: string;
    kind?: string;
    name?: string;
}
export interface ScanProgress {
    progress: number;
    currentStep: string;
}
export declare function scanKubernetes(yaml: string, job: Job, scanId: string): Promise<KubernetesScanResult>;
export declare function fixKubernetes(yaml: string, findings: KubernetesFinding[], job: Job): Promise<{
    fixedYaml: string;
    changes: any[];
}>;
export declare function generateKubernetes(spec: any, job: Job): Promise<{
    yaml: string;
}>;
//# sourceMappingURL=index.d.ts.map