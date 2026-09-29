import { Job } from 'bullmq';
export interface DependencyScanResult {
    summary: {
        totalDependencies: number;
        vulnerabilities: {
            critical: number;
            high: number;
            medium: number;
            low: number;
            info: number;
        };
        outdated: number;
        licenses: Record<string, number>;
    };
    dependencies: DependencyInfo[];
    findings: DependencyFinding[];
    sbom?: any;
}
export interface DependencyInfo {
    name: string;
    version: string;
    type: string;
    location?: string;
    licenses?: string[];
    homepage?: string;
    repository?: string;
    description?: string;
    latestVersion?: string;
    outdated?: boolean;
    purl?: string;
    cpe?: string;
}
export interface DependencyFinding {
    id: string;
    type: 'vulnerability' | 'license' | 'outdated' | 'malicious';
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    title: string;
    description: string;
    package: string;
    version: string;
    fixedVersion?: string;
    cve?: string;
    cwe?: string;
    cvss?: number;
    references?: string[];
    file?: string;
    line?: number;
}
export interface SBOMData {
    packages: SBOMPackage[];
    relationships: SBOMRelationship[];
    metadata: SBOMMetadata;
}
export interface SBOMPackage {
    name: string;
    version: string;
    type: string;
    licenses: string[];
    homepage?: string;
    repository?: string;
    description?: string;
    cpe?: string;
    purl?: string;
    hashes?: Record<string, string>;
}
export interface SBOMRelationship {
    refA: string;
    refB: string;
    type: string;
}
export interface SBOMMetadata {
    timestamp: string;
    tool: string;
    component?: {
        name: string;
        version: string;
    };
}
export interface ScanProgress {
    progress: number;
    currentStep: string;
}
export declare function scanDependencies(input: {
    repoUrl?: string;
    branch?: string;
    manifest?: string;
    format?: string;
    filename?: string;
}, job: Job, scanId: string): Promise<DependencyScanResult>;
export declare function remediateDependency(scanId: string, packageName: string, currentVersion: string, job: Job): Promise<{
    updatedManifest: string;
    changes: any[];
}>;
export declare function generateSBOM(scanId: string, format: 'cyclonedx' | 'spdx', job: Job): Promise<{
    sbom: SBOMData;
}>;
//# sourceMappingURL=index.d.ts.map