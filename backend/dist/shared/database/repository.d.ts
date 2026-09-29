import type { ApiKey, AuditLog, Finding, GitHubRepository, GitHubScan, Job, LogEntry, LogFile, Notification, Scan, Settings, User } from './types';
/**
 * A small Prisma-shaped data layer over the InsForge admin client.
 *
 * The route modules were written against Prisma's fluent API. Rather than
 * rewriting every call site, this exposes the same verbs (findMany,
 * findUnique, createMany, upsert, groupBy, ...) translated onto the PostgREST
 * query builder, with camelCase in and snake_case at the wire.
 *
 * Supported `where` shapes: scalar equality, `{ in: [...] }`,
 * `{ contains, mode }`, `null`, and `OR` arrays of those. That covers every
 * filter the current routes build.
 */
type Row = Record<string, unknown>;
export interface Where {
    [key: string]: unknown;
}
type IncludeSpec = true | Record<string, unknown>;
export interface FindArgs<K extends string = string> {
    where?: Where;
    orderBy?: Record<string, 'asc' | 'desc'> | Record<string, 'asc' | 'desc'>[];
    take?: number;
    skip?: number;
    include?: {
        [P in K]?: IncludeSpec;
    } | Record<string, IncludeSpec>;
    select?: Record<string, boolean>;
}
/**
 * A Prisma-shaped repository. `R` declares which relations can be `include`d;
 * including one narrows the result to `T & Pick<R, K>` so the call sites keep
 * the precise types they had under Prisma.
 */
export interface Repository<T = Row, R extends Record<string, unknown> = Record<string, unknown>> {
    findMany<K extends keyof R = never>(args?: FindArgs<Extract<keyof R, string>> & {
        include?: {
            [P in K]?: IncludeSpec;
        };
    }): Promise<Array<T & Pick<R, K>>>;
    findUnique<K extends keyof R = never>(args: {
        where: Where;
        include?: {
            [P in K]?: IncludeSpec;
        };
        select?: Record<string, boolean>;
    }): Promise<(T & Pick<R, K>) | null>;
    findFirst<K extends keyof R = never>(args?: FindArgs<Extract<keyof R, string>> & {
        include?: {
            [P in K]?: IncludeSpec;
        };
    }): Promise<(T & Pick<R, K>) | null>;
    create(args: {
        data: Where;
        select?: Record<string, boolean>;
    }): Promise<T>;
    createMany(args: {
        data: Where[];
    }): Promise<{
        count: number;
    }>;
    update(args: {
        where: Where;
        data: Where;
        select?: Record<string, boolean>;
    }): Promise<T | null>;
    updateMany(args: {
        where: Where;
        data: Where;
    }): Promise<{
        count: number;
    }>;
    upsert(args: {
        where: Where;
        create: Where;
        update: Where;
    }): Promise<T>;
    delete(args: {
        where: Where;
    }): Promise<T | null>;
    deleteMany(args: {
        where: Where;
    }): Promise<{
        count: number;
    }>;
    count(args?: {
        where?: Where;
    }): Promise<number>;
}
export interface GroupCountRow {
    [key: string]: string | number | null;
    _count: number;
}
export interface GroupByArgs {
    by: string[];
    where?: Where;
    _count?: boolean;
}
export type Groupable = {
    groupBy(args: GroupByArgs): Promise<GroupCountRow[]>;
};
export interface Database {
    user: Repository<User, {
        settings: Settings;
    }>;
    settings: Repository<Settings>;
    scan: Repository<Scan, {
        findings: Finding[];
    }> & Groupable;
    finding: Repository<Finding, {
        scan: Scan;
    }>;
    job: Repository<Job> & Groupable;
    logFile: Repository<LogFile, {
        entries: LogEntry[];
    }>;
    logEntry: Repository<LogEntry> & Groupable;
    gitHubRepository: Repository<GitHubRepository, {
        scans: GitHubScan[];
    }>;
    githubScan: Repository<GitHubScan>;
    notification: Repository<Notification>;
    apiKey: Repository<ApiKey>;
    auditLog: Repository<AuditLog>;
}
export declare function createDatabase(): Database;
export declare const db: Database;
export {};
//# sourceMappingURL=repository.d.ts.map