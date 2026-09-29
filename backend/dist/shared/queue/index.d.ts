import { JobType } from '@devsecops/shared/types';
interface JobData {
    type: JobType;
    input: Record<string, unknown>;
    userId: string;
    scanId?: string;
    jobId?: string;
}
/**
 * The queue needs Redis. When it is not configured we keep the HTTP API fully
 * usable (auth, scans listing, logs, settings, SBOM export) and fail only the
 * endpoints that actually enqueue work, instead of log-spamming reconnect
 * errors from a worker that can never reach Redis.
 */
export declare const queueAvailable: () => boolean;
export declare class QueueUnavailableError extends Error {
    constructor();
}
export declare function initializeQueue(): Promise<void>;
export declare function shutdownQueue(): Promise<void>;
export declare function createJob(data: JobData, priority?: 'low' | 'normal' | 'high'): Promise<string>;
export declare function getJobStatus(jobId: string): Promise<any>;
export declare function cancelJob(jobId: string): Promise<boolean>;
export {};
//# sourceMappingURL=index.d.ts.map