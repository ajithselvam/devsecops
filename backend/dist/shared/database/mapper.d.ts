/**
 * Column name mapping between the camelCase shapes the route handlers already
 * use and the snake_case Postgres columns, plus the jsonb <-> string
 * transcoding the legacy code expects.
 */
type ColumnMap = Record<string, string>;
export declare const TABLE_COLUMNS: {
    profiles: ColumnMap;
    settings: ColumnMap;
    scans: ColumnMap;
    findings: ColumnMap;
    jobs: ColumnMap;
    log_files: ColumnMap;
    log_entries: ColumnMap;
    github_repositories: ColumnMap;
    github_scans: ColumnMap;
    notifications: ColumnMap;
    api_keys: ColumnMap;
    audit_logs: ColumnMap;
};
/**
 * TS field -> Postgres column where the name is not a plain snake_case
 * conversion: SQL reserved words and deliberately different names.
 */
export declare const COLUMN_OVERRIDES: Record<string, ColumnMap>;
export type TableName = keyof typeof TABLE_COLUMNS;
export declare function toColumn(table: TableName, field: string): string;
/** camelCase field name -> Postgres column, for a whole payload. */
export declare function toColumns(table: TableName, payload: Record<string, unknown>): Record<string, unknown>;
/** Postgres column -> camelCase field name, for a whole row. */
export declare function toFields(table: TableName, row: Record<string, unknown> | null): Record<string, unknown> | null;
export declare function toRows<T = Record<string, unknown>>(table: TableName, rows: Record<string, unknown>[] | null | undefined): T[];
export {};
//# sourceMappingURL=mapper.d.ts.map