import { Job } from 'bullmq';
export interface LogInvestigationResult {
    rootCause: string;
    evidence: LogEvidence[];
    timeline: LogTimelineEvent[];
    recommendations: string[];
    relatedPatterns: LogPattern[];
}
export interface LogEvidence {
    id: string;
    type: 'error' | 'warning' | 'exception' | 'timeout' | 'resource' | 'config' | 'network' | 'security';
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    description: string;
    logLines: LogLine[];
    timestamp?: string;
    source?: string;
}
export interface LogLine {
    lineNumber: number;
    timestamp?: string;
    level?: string;
    message: string;
    raw: string;
}
export interface LogTimelineEvent {
    timestamp: string;
    event: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    source: string;
    relatedLines: number[];
}
export interface LogPattern {
    pattern: string;
    description: string;
    count: number;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    examples: string[];
}
export interface LogSearchResult {
    matches: LogMatch[];
    totalMatches: number;
    scannedLines: number;
}
export interface LogMatch {
    lineNumber: number;
    timestamp?: string;
    level?: string;
    message: string;
    context: {
        before: string[];
        after: string[];
    };
    file: string;
}
export interface ScanProgress {
    progress: number;
    currentStep: string;
}
export declare function investigateLogs(question: string, logEntries: any[], context: any, job: Job): Promise<LogInvestigationResult>;
export declare function searchLogs(query: string, logFiles: string[], options: {
    caseSensitive?: boolean;
    regex?: boolean;
    before?: number;
    after?: number;
} | undefined, job: Job): Promise<LogSearchResult>;
export declare function parseLogFile(filePath: string, job: Job): Promise<any[]>;
export declare function getLogStats(logFiles: string[], job: Job): Promise<{
    totalLines: number;
    totalFiles: number;
    totalSize: number;
    levelDistribution: Record<string, number>;
    timeRange: {
        start: string;
        end: string;
    } | null;
}>;
//# sourceMappingURL=index.d.ts.map