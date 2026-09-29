/**
 * Column name mapping between the camelCase shapes the route handlers already
 * use and the snake_case Postgres columns, plus the jsonb <-> string
 * transcoding the legacy code expects.
 */

type ColumnMap = Record<string, string>;

/** Columns whose Postgres name is a straight snake_case of the TS name. */
const auto = (names: string[]): ColumnMap =>
  Object.fromEntries(names.map((n) => [n, n.replace(/[A-Z]/g, (c) => `_${c.toLowerCase()}`)]));

export const TABLE_COLUMNS = {
  profiles: auto([
    'id', 'name', 'avatarUrl', 'role', 'theme', 'sidebarCollapsed', 'language',
    'emailNotifications', 'inAppNotifications', 'notifyScanComplete',
    'notifyScanFailed', 'notifyVulnFound', 'notifyJobChange',
    'lastLoginAt', 'createdAt', 'updatedAt'
  ]),

  settings: auto([
    'id', 'userId', 'aiProvider', 'aiAppsScriptUrl', 'aiOpenaiKey', 'aiGeminiKey',
    'aiAnthropicKey', 'aiDefaultModel', 'aiTemperature', 'aiMaxTokens',
    'dockerHubUsername', 'dockerHubToken', 'dockerRegistry', 'dockerBuildTimeout',
    'dockerScanTimeout', 'githubAppId', 'githubPrivateKey', 'githubWebhookSecret',
    'githubDefaultOrg', 'githubToken', 'gitlabToken', 'bitbucketToken',
    'slackWebhook', 'teamsWebhook', 'jiraUrl', 'jiraToken', 'webhookUrl',
    'webhookSecret', 'scanningDefaultTools', 'scanningMaxConcurrent',
    'scanningTimeout', 'debugMode', 'telemetryEnabled', 'autoUpdate',
    'createdAt', 'updatedAt'
  ]),

  scans: auto([
    'id', 'userId', 'type', 'status', 'targetType', 'targetValue', 'summary',
    'jobId', 'artifactKey', 'artifactUrl', 'completedAt', 'createdAt', 'updatedAt'
  ]),

  findings: auto([
    'id', 'userId', 'scanId', 'type', 'severity', 'title', 'description', 'file', 'line',
    'code', 'ruleId', 'ruleName', 'cve', 'package', 'installedVersion',
    'fixedVersion', 'cvssScore', 'cwe', 'references', 'remediation', 'status',
    'createdAt', 'updatedAt'
  ]),

  jobs: auto([
    'id', 'userId', 'type', 'status', 'progress', 'currentStep', 'totalSteps',
    'input', 'output', 'error', 'scanId', 'startedAt', 'completedAt',
    'createdAt', 'updatedAt'
  ]),

  log_files: auto([
    'id', 'userId', 'name', 'size', 'lineCount', 'format', 'indexed',
    'storageKey', 'storageUrl', 'createdAt', 'updatedAt'
  ]),

  log_entries: auto([
    'id', 'userId', 'logFileId', 'timestamp', 'level', 'service', 'message', 'raw',
    'fields', 'indexed', 'createdAt'
  ]),

  github_repositories: auto([
    'id', 'userId', 'githubId', 'name', 'fullName', 'url', 'cloneUrl',
    'defaultBranch', 'private', 'connectedAt', 'lastScannedAt',
    'createdAt', 'updatedAt'
  ]),

  github_scans: auto([
    'id', 'userId', 'repoId', 'branch', 'commitSha', 'sbom', 'summary',
    'vulnerabilities', 'secrets', 'codeIssues', 'depIssues', 'scanTime', 'createdAt'
  ]),

  notifications: auto([
    'id', 'userId', 'type', 'title', 'message', 'read', 'actionUrl', 'metadata',
    'createdAt', 'updatedAt'
  ]),

  api_keys: auto([
    'id', 'userId', 'name', 'keyHash', 'prefix', 'lastUsedAt', 'expiresAt',
    'revokedAt', 'createdAt', 'updatedAt'
  ]),

  audit_logs: auto([
    'id', 'userId', 'action', 'resource', 'resourceId', 'ip', 'userAgent', 'createdAt'
  ])
} satisfies Record<string, ColumnMap>;

/**
 * TS field -> Postgres column where the name is not a plain snake_case
 * conversion: SQL reserved words and deliberately different names.
 */
export const COLUMN_OVERRIDES: Record<string, ColumnMap> = {
  scans: { targetMeta: 'target_meta' },

  findings: {
    // `column` and `references` are SQL reserved words.
    column: 'column_index',
    references: 'reference_urls'
  },

  notifications: { read: 'is_read' }
};

/**
 * Columns stored as jsonb. The legacy route handlers `JSON.stringify` on write
 * and `JSON.parse` on read, so the data layer transcodes at the boundary to keep
 * the HTTP contract byte-identical while Postgres keeps a real JSON type.
 */
const JSONB_COLUMNS: Record<string, string[]> = {
  settings: ['scanning_default_tools'],

  scans: ['target_meta', 'summary'],

  findings: ['reference_urls'],

  jobs: ['input', 'output'],

  log_entries: ['fields'],

  github_scans: ['sbom', 'summary', 'vulnerabilities', 'secrets', 'code_issues', 'dep_issues'],

  notifications: ['metadata'],

  audit_logs: ['metadata']
};

export type TableName = keyof typeof TABLE_COLUMNS;

export function toColumn(table: TableName, field: string): string {
  return COLUMN_OVERRIDES[table]?.[field] ?? TABLE_COLUMNS[table]?.[field] ?? field;
}

/** jsonb column + legacy string -> a real JSON value for Postgres. */
function encodeJsonb(column: string, value: unknown): unknown {
  if (typeof value !== 'string') return value;
  try {
    return JSON.parse(value) as unknown;
  } catch {
    // Not JSON (e.g. free text); store the literal string.
    return value;
  }
}

/** jsonb column -> the JSON string the legacy callers expect to parse. */
function decodeJsonb(value: unknown): unknown {
  return value === null || value === undefined ? value : JSON.stringify(value);
}

/**
 * Prisma callers pass BigInt for `bigint` columns (e.g. `log_files.size`), but
 * JSON.stringify throws on BigInt, so the PostgREST client rejects the write.
 * Postgres bigint values here stay well inside the JS safe-integer range.
 */
function encodeBigint(value: unknown): unknown {
  return typeof value === 'bigint' ? Number(value) : value;
}

/** camelCase field name -> Postgres column, for a whole payload. */
export function toColumns(table: TableName, payload: Record<string, unknown>): Record<string, unknown> {
  const jsonb = new Set(JSONB_COLUMNS[table] ?? []);
  const out: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(payload)) {
    if (value === undefined) continue;
    const column = toColumn(table, key);
    const encoded = jsonb.has(column) ? encodeJsonb(column, value) : value;
    out[column] = encodeBigint(encoded);
  }
  return out;
}

/** Postgres column -> camelCase field name, for a whole row. */
export function toFields(table: TableName, row: Record<string, unknown> | null): Record<string, unknown> | null {
  if (!row) return null;

  const jsonb = new Set(JSONB_COLUMNS[table] ?? []);

  const reverse: Record<string, string> = {};
  for (const field of Object.keys(TABLE_COLUMNS[table])) {
    reverse[toColumn(table, field)] = field;
  }
  for (const [field, column] of Object.entries(COLUMN_OVERRIDES[table] ?? {})) {
    reverse[column] = field;
  }
  reverse.user_id = 'userId';

  const out: Record<string, unknown> = {};
  for (const [column, value] of Object.entries(row)) {
    const field = reverse[column] ?? column;
    out[field] = jsonb.has(column) ? decodeJsonb(value) : value;
  }
  return out;
}

export function toRows<T = Record<string, unknown>>(
  table: TableName,
  rows: Record<string, unknown>[] | null | undefined
): T[] {
  return (rows ?? []).map((row) => toFields(table, row) as T);
}
