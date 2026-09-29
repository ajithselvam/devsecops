/**
 * Generates a Postgres SQL file from the legacy SQLite database so it can be
 * loaded into InsForge with `npx insforge db import`.
 *
 *   node scripts/export-legacy-sql.mjs [path/to/dev.db] [out.sql]
 *
 * Notes:
 *  - `auth.users` is written directly because the platform exposes no admin user
 *    API. The legacy bcrypt `$2b$` hashes are the format InsForge verifies.
 *  - Imported users are marked email_verified so they can sign in immediately.
 *  - Legacy timestamps are epoch milliseconds (Prisma/SQLite); Postgres wants
 *    timestamptz, so they go through to_timestamp().
 *  - Columns that are jsonb in Postgres are inlined as JSON. A value that is not
 *    valid JSON is stored as a JSON string so nothing is lost.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const sqlitePath = resolve(process.argv[2] ?? resolve(here, '../prisma/dev.db'));
const outPath = resolve(process.argv[3] ?? resolve(here, '../../migrations/legacy-data.sql'));

const sqlite = new DatabaseSync(sqlitePath, { readOnly: true });
const rows = (table) => sqlite.prepare(`SELECT * FROM "${table}"`).all();

/* ---------------------------- literals ---------------------------- */

const quote = (value) => `'${String(value).replace(/'/g, "''")}'`;

/** A target column: its Postgres name plus how to render values. */
const col = (name, kind = 'text') => ({ name, kind });

/** Values above this size are staged in slices instead of inlined. */
const OVERSIZED = 60 * 1024;
const CHUNK_SIZE = 60 * 1024;
/** macOS caps a single argv entry at 262144 bytes, so keep statements well under. */
const STATEMENT_LIMIT = 150 * 1024;

function literal(value, kind) {
  if (value === null || value === undefined) return 'NULL';

  switch (kind) {
    case 'timestamp': {
      const ms = Number(value);
      return Number.isFinite(ms) ? `to_timestamp(${ms} / 1000.0)` : 'NULL';
    }
    case 'json': {
      const text = String(value);
      try {
        return `${quote(JSON.stringify(JSON.parse(text)))}::jsonb`;
      } catch {
        // Free text living in a jsonb column.
        return `${quote(JSON.stringify(text))}::jsonb`;
      }
    }
    case 'number':
      return Number.isFinite(Number(value)) ? String(Number(value)) : 'NULL';
    case 'bool':
      return Number(value) ? 'true' : 'false';
    case 'uuid':
      return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(value))
        ? quote(value)
        : 'NULL';
    case 'int':
      return Number.isFinite(Number(value)) ? String(Math.trunc(Number(value))) : 'NULL';
    default:
      return quote(value);
  }
}

function insert(table, columns, records, { batch = 50, staged = [] } = {}) {
  if (records.length === 0) return [`-- ${table}: nothing to import`];

  // Multi-megabyte values (a repo scan keeps a full SBOM in target_meta) exceed
  // the shell's argument limit, so they are staged in slices and reassembled.
  const staging = [];
  for (const record of records) {
    for (const name of staged) {
      const value = record[name];
      if (typeof value !== 'string' || value.length <= OVERSIZED) continue;
      staging.push({ ref: `${table}:${record.id}:${name}`, value });
      record[name] = null;
    }
  }

  const names = columns.map((c) => c.name).join(', ');
  const prefix = `INSERT INTO public.${table} (${names}) VALUES\n`;
  const suffix = `\nON CONFLICT DO NOTHING;`;

  // Batch by row count, but flush early so a statement stays under the limit.
  const statements = [];
  let pending = [];
  let pendingSize = 0;
  const flush = () => {
    if (pending.length === 0) return;
    statements.push(prefix + pending.join(',\n') + suffix);
    pending = [];
    pendingSize = 0;
  };

  for (const record of records) {
    const row = `  (${columns.map((c) => literal(record[c.name], c.kind)).join(', ')})`;
    if (pending.length >= batch || (pending.length > 0 && pendingSize + row.length > STATEMENT_LIMIT)) {
      flush();
    }
    pending.push(row);
    pendingSize += row.length;
  }
  flush();

  if (staging.length > 0) statements.push(...stageValues(staging));
  return statements;
}

/** Never splits a surrogate pair, so reassembly is byte-exact. */
function splitSafe(text, size) {
  const parts = [];
  for (let i = 0; i < text.length; ) {
    let end = Math.min(i + size, text.length);
    if (end < text.length) {
      const code = text.charCodeAt(end - 1);
      if (code >= 0xd800 && code <= 0xdbff) end -= 1;
    }
    parts.push(text.slice(i, end));
    i = end;
  }
  return parts;
}

function stageValues(staging) {
  const statements = [
    `CREATE TABLE IF NOT EXISTS public._import_chunks (
  ref text not null,
  seq int not null,
  chunk text not null,
  primary key (ref, seq)
);`
  ];

  // Append slices in multi-row statements, staying under the argument limit.
  const rows = [];
  let pendingSize = 0;
  const flush = () => {
    if (rows.length === 0) return;
    statements.push(
      `INSERT INTO public._import_chunks (ref, seq, chunk) VALUES\n${rows.join(',\n')}\nON CONFLICT DO NOTHING;`
    );
    rows.length = 0;
    pendingSize = 0;
  };

  for (const item of staging) {
    splitSafe(item.value, CHUNK_SIZE).forEach((chunk, seq) => {
      const row = `  (${quote(item.ref)}, ${seq}, ${quote(chunk)})`;
      if (rows.length > 0 && pendingSize + row.length > STATEMENT_LIMIT) flush();
      pendingSize += row.length;
      rows.push(row);
    });
    flush();
  }

  for (const item of staging) {
    statements.push(
      `UPDATE public.${item.ref.split(':')[0]} AS t
SET ${item.ref.split(':')[2]} = (
  SELECT string_agg(chunk, '' ORDER BY seq) FROM public._import_chunks WHERE ref = ${quote(item.ref)}
)::jsonb
WHERE t.id = ${quote(item.ref.split(':')[1])};`
    );
  }

  return statements;
}

/* ------------------------------ data ------------------------------ */

const users = rows('User');
const settings = rows('Settings');
const scans = rows('Scan');
const findings = rows('Finding');
const jobs = rows('Job');
const logFiles = rows('LogFile');
const logEntries = rows('LogEntry');
const repos = rows('GitHubRepository');
const githubScans = rows('GitHubScan');
const notifications = rows('Notification');
const apiKeys = rows('ApiKey');
const auditLogs = rows('AuditLog');

const scanOwner = new Map(scans.map((scan) => [scan.id, scan.userId]));
const logFileOwner = new Map(logFiles.map((logFile) => [logFile.id, logFile.userId]));
const repoOwner = new Map(repos.map((repo) => [repo.id, repo.userId]));

/** Renames legacy camelCase keys onto the target column names. */
const from = (record, mapping) => {
  const out = {};
  for (const [target, source] of Object.entries(mapping)) {
    out[target] = record[source];
  }
  return out;
};

/** Every element of `statements` is one SQL statement or comment block. */
const statements = [];
const add = (...items) => statements.push(...items.flat());

const STATEMENT_SEPARATOR = '\n-- @@\n';

const authUserInsert = [
  'INSERT INTO auth.users (id, email, password, email_verified, created_at, updated_at, profile, metadata, is_project_admin, is_anonymous) VALUES',
  users
    .map(
      (user) =>
        `  (${quote(user.id)}, ${quote(user.email)}, ${quote(user.passwordHash)}, true, ` +
        `${literal(user.createdAt, 'timestamp')}, ${literal(user.updatedAt, 'timestamp')}, ` +
        `${quote(JSON.stringify({ name: user.name, ...(user.avatarUrl ? { avatar_url: user.avatarUrl } : {}) }))}::jsonb, ` +
        `'{}'::jsonb, false, false)`
    )
    .join(',\n'),
  'ON CONFLICT (id) DO NOTHING;'
].join('\n');

// The on_auth_user_created trigger seeds public.profiles; this carries over the
// legacy preferences.
const profileUpdate = [
  'UPDATE public.profiles AS p SET',
  '  name = v.name, avatar_url = v.avatar_url, role = v.role, theme = v.theme,',
  '  sidebar_collapsed = v.sidebar_collapsed, language = v.language,',
  '  email_notifications = v.email_notifications, in_app_notifications = v.in_app_notifications,',
  '  notify_scan_complete = v.notify_scan_complete, notify_scan_failed = v.notify_scan_failed,',
  '  notify_vuln_found = v.notify_vuln_found, notify_job_change = v.notify_job_change,',
  '  last_login_at = v.last_login_at',
  'FROM (VALUES',
  users
    .map(
      (user) =>
        `  (${quote(user.id)}::uuid, ${quote(user.name)}, ${literal(user.avatarUrl)}, ${quote(user.role)}, ` +
        `${quote(user.theme)}, ${literal(user.sidebarCollapsed, 'bool')}, ${quote(user.language)}, ` +
        `${literal(user.emailNotifications, 'bool')}, ${literal(user.inAppNotifications, 'bool')}, ` +
        `${literal(user.notifyScanComplete, 'bool')}, ${literal(user.notifyScanFailed, 'bool')}, ` +
        `${literal(user.notifyVulnFound, 'bool')}, ${literal(user.notifyJobChange, 'bool')}, ` +
        `${literal(user.lastLoginAt, 'timestamp')})`
    )
    .join(',\n'),
  ') AS v(id, name, avatar_url, role, theme, sidebar_collapsed, language,',
  '      email_notifications, in_app_notifications, notify_scan_complete,',
  '      notify_scan_failed, notify_vuln_found, notify_job_change, last_login_at)',
  'WHERE p.id = v.id;'
].join('\n');

add(
  '-- Generated by backend/scripts/export-legacy-sql.mjs from backend/prisma/dev.db',
  '-- Load with: node scripts/import-legacy-sql.mjs',
  '-- Legacy bcrypt ($2a$12$) hashes are the format InsForge verifies, so existing',
  '-- passwords keep working. Verified so the accounts can sign in immediately.',
  authUserInsert,
  '',
  profileUpdate,
  ''
);

add(
  insert(
    'settings',
    [
      col('id', 'uuid'), col('user_id', 'uuid'), col('ai_provider'), col('ai_apps_script_url'),
      col('ai_openai_key'), col('ai_gemini_key'), col('ai_anthropic_key'), col('ai_default_model'),
      col('ai_temperature', 'number'), col('ai_max_tokens', 'int'),
      col('docker_hub_username'), col('docker_hub_token'), col('docker_registry'),
      col('docker_build_timeout', 'int'), col('docker_scan_timeout', 'int'),
      col('github_app_id'), col('github_private_key'), col('github_webhook_secret'),
      col('github_default_org'), col('github_token'), col('gitlab_token'), col('bitbucket_token'),
      col('slack_webhook'), col('teams_webhook'), col('jira_url'), col('jira_token'),
      col('webhook_url'), col('webhook_secret'),
      col('scanning_default_tools', 'json'), col('scanning_max_concurrent', 'int'),
      col('scanning_timeout', 'int'), col('debug_mode', 'bool'), col('telemetry_enabled', 'bool'),
      col('auto_update', 'bool'), col('created_at', 'timestamp'), col('updated_at', 'timestamp')
    ],
    settings.map((r) =>
      from(r, {
        id: 'id', user_id: 'userId', ai_provider: 'aiProvider', ai_apps_script_url: 'aiAppsScriptUrl',
        ai_openai_key: 'aiOpenaiKey', ai_gemini_key: 'aiGeminiKey', ai_anthropic_key: 'aiAnthropicKey',
        ai_default_model: 'aiDefaultModel', ai_temperature: 'aiTemperature', ai_max_tokens: 'aiMaxTokens',
        docker_hub_username: 'dockerHubUsername', docker_hub_token: 'dockerHubToken',
        docker_registry: 'dockerRegistry', docker_build_timeout: 'dockerBuildTimeout',
        docker_scan_timeout: 'dockerScanTimeout', github_app_id: 'githubAppId',
        github_private_key: 'githubPrivateKey', github_webhook_secret: 'githubWebhookSecret',
        github_default_org: 'githubDefaultOrg', github_token: 'githubToken',
        gitlab_token: 'gitlabToken', bitbucket_token: 'bitbucketToken',
        slack_webhook: 'slackWebhook', teams_webhook: 'teamsWebhook', jira_url: 'jiraUrl',
        jira_token: 'jiraToken', webhook_url: 'webhookUrl', webhook_secret: 'webhookSecret',
        scanning_default_tools: 'scanningDefaultTools',
        scanning_max_concurrent: 'scanningMaxConcurrent', scanning_timeout: 'scanningTimeout',
        debug_mode: 'debugMode', telemetry_enabled: 'telemetryEnabled', auto_update: 'autoUpdate',
        created_at: 'createdAt', updated_at: 'updatedAt'
      })
    )
  ),
  ''
);

add(
  insert(
    'jobs',
    [
      col('id', 'uuid'), col('user_id', 'uuid'), col('type'), col('status'),
      col('progress', 'int'), col('current_step'), col('total_steps', 'int'),
      col('input', 'json'), col('output', 'json'), col('error'), col('scan_id', 'uuid'),
      col('started_at', 'timestamp'), col('completed_at', 'timestamp'),
      col('created_at', 'timestamp'), col('updated_at', 'timestamp')
    ],
    jobs.map((r) =>
      from(r, {
        id: 'id', user_id: 'userId', type: 'type', status: 'status', progress: 'progress',
        current_step: 'currentStep', total_steps: 'totalSteps', input: 'input', output: 'output',
        error: 'error', scan_id: 'scanId', started_at: 'startedAt', completed_at: 'completedAt',
        created_at: 'createdAt', updated_at: 'updatedAt'
      })
    )
  ),
  ''
);

add(
  insert(
    'scans',
    [
      col('id', 'uuid'), col('user_id', 'uuid'), col('type'), col('status'), col('target_type'),
      col('target_value'), col('target_meta', 'json'), col('summary', 'json'), col('job_id', 'uuid'),
      col('completed_at', 'timestamp'), col('created_at', 'timestamp'), col('updated_at', 'timestamp')
    ],
    scans.map((r) =>
      from(r, {
        id: 'id', user_id: 'userId', type: 'type', status: 'status', target_type: 'targetType',
        target_value: 'targetValue', target_meta: 'targetMeta', summary: 'summary', job_id: 'jobId',
        completed_at: 'completedAt', created_at: 'createdAt', updated_at: 'updatedAt'
      })
    ),
    { staged: ['target_meta'] }
  ),
  ''
);

add(
  insert(
    'findings',
    [
      col('id', 'uuid'), col('user_id', 'uuid'), col('scan_id', 'uuid'), col('type'),
      col('severity'), col('title'), col('description'), col('file'), col('line', 'int'),
      col('column_index', 'int'), col('code'), col('rule_id'), col('rule_name'), col('cve'),
      col('package'), col('installed_version'), col('fixed_version'), col('cvss_score', 'number'),
      col('cwe'), col('reference_urls', 'json'), col('remediation'), col('status'),
      col('created_at', 'timestamp'), col('updated_at', 'timestamp')
    ],
    findings.map((r) => ({
      ...from(r, {
        id: 'id', scan_id: 'scanId', type: 'type', severity: 'severity', title: 'title',
        description: 'description', file: 'file', line: 'line', column_index: 'column', code: 'code',
        rule_id: 'ruleId', rule_name: 'ruleName', cve: 'cve', package: 'package',
        installed_version: 'installedVersion', fixed_version: 'fixedVersion',
        cvss_score: 'cvssScore', cwe: 'cwe', reference_urls: 'references',
        remediation: 'remediation', status: 'status', created_at: 'createdAt', updated_at: 'updatedAt'
      }),
      user_id: scanOwner.get(r.scanId) ?? null
    }))
  ),
  ''
);

add(
  insert(
    'log_files',
    [
      col('id', 'uuid'), col('user_id', 'uuid'), col('name'), col('size', 'number'),
      col('line_count', 'int'), col('format'), col('indexed', 'bool'),
      col('created_at', 'timestamp'), col('updated_at', 'timestamp')
    ],
    logFiles.map((r) =>
      from(r, {
        id: 'id', user_id: 'userId', name: 'name', size: 'size', line_count: 'lineCount',
        format: 'format', indexed: 'indexed', created_at: 'createdAt', updated_at: 'updatedAt'
      })
    )
  ),
  ''
);

add(
  insert(
    'log_entries',
    [
      col('id', 'uuid'), col('user_id', 'uuid'), col('log_file_id', 'uuid'), col('timestamp', 'timestamp'),
      col('level'), col('service'), col('message'), col('raw'), col('fields', 'json'),
      col('indexed', 'bool'), col('created_at', 'timestamp')
    ],
    logEntries.map((r) => ({
      ...from(r, {
        id: 'id', log_file_id: 'logFileId', timestamp: 'timestamp', level: 'level',
        service: 'service', message: 'message', raw: 'raw', fields: 'fields', indexed: 'indexed',
        created_at: 'createdAt'
      }),
      user_id: logFileOwner.get(r.logFileId) ?? null
    }))
  ),
  ''
);

add(
  insert(
    'github_repositories',
    [
      col('id', 'uuid'), col('user_id', 'uuid'), col('github_id', 'number'), col('name'),
      col('full_name'), col('url'), col('clone_url'), col('default_branch'), col('private', 'bool'),
      col('connected_at', 'timestamp'), col('last_scanned_at', 'timestamp'),
      col('created_at', 'timestamp'), col('updated_at', 'timestamp')
    ],
    repos.map((r) => ({
      ...from(r, {
        id: 'id', user_id: 'userId', github_id: 'githubId', name: 'name', full_name: 'fullName',
        url: 'url', clone_url: 'cloneUrl', default_branch: 'defaultBranch', private: 'private',
        connected_at: 'connectedAt', last_scanned_at: 'lastScannedAt', created_at: 'connectedAt',
        updated_at: 'connectedAt'
      })
    }))
  ),
  ''
);

add(
  insert(
    'github_scans',
    [
      col('id', 'uuid'), col('user_id', 'uuid'), col('repo_id', 'uuid'), col('branch'),
      col('commit_sha'), col('sbom', 'json'), col('summary', 'json'), col('vulnerabilities', 'json'),
      col('secrets', 'json'), col('code_issues', 'json'), col('dep_issues', 'json'),
      col('scan_time', 'timestamp'), col('created_at', 'timestamp')
    ],
    githubScans.map((r) => ({
      ...from(r, {
        id: 'id', repo_id: 'repoId', branch: 'branch', commit_sha: 'commitSha', sbom: 'sbom',
        summary: 'summary', vulnerabilities: 'vulnerabilities', secrets: 'secrets',
        code_issues: 'codeIssues', dep_issues: 'depIssues', scan_time: 'scanTime',
        created_at: 'createdAt'
      }),
      user_id: repoOwner.get(r.repoId) ?? null
    }))
  ),
  ''
);

add(
  insert(
    'notifications',
    [
      col('id', 'uuid'), col('user_id', 'uuid'), col('type'), col('title'), col('message'),
      col('is_read', 'bool'), col('action_url'), col('metadata', 'json'),
      col('created_at', 'timestamp'), col('updated_at', 'timestamp')
    ],
    notifications.map((r) => ({
      ...from(r, {
        id: 'id', user_id: 'userId', type: 'type', title: 'title', message: 'message',
        is_read: 'read', action_url: 'actionUrl', metadata: 'metadata',
        created_at: 'createdAt', updated_at: 'createdAt'
      })
    }))
  ),
  ''
);

add(
  insert(
    'api_keys',
    [
      col('id', 'uuid'), col('user_id', 'uuid'), col('name'), col('key_hash'), col('prefix'),
      col('last_used_at', 'timestamp'), col('expires_at', 'timestamp'), col('revoked_at', 'timestamp'),
      col('created_at', 'timestamp'), col('updated_at', 'timestamp')
    ],
    apiKeys.map((r) =>
      from(r, {
        id: 'id', user_id: 'userId', name: 'name', key_hash: 'keyHash', prefix: 'prefix',
        last_used_at: 'lastUsedAt', expires_at: 'expiresAt', revoked_at: 'revokedAt',
        created_at: 'createdAt', updated_at: 'createdAt'
      })
    )
  ),
  ''
);

add(
  insert(
    'audit_logs',
    [
      col('id', 'uuid'), col('user_id', 'uuid'), col('action'), col('resource'),
      col('resource_id', 'uuid'), col('metadata', 'json'), col('ip'), col('user_agent'),
      col('created_at', 'timestamp')
    ],
    auditLogs.map((r) =>
      from(r, {
        id: 'id', user_id: 'userId', action: 'action', resource: 'resource',
        resource_id: 'resourceId', metadata: 'metadata', ip: 'ip', user_agent: 'userAgent',
        created_at: 'createdAt'
      })
    )
  ),
  ''
);

add('DROP TABLE IF EXISTS public._import_chunks;');

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, statements.join(STATEMENT_SEPARATOR) + '\n');

console.log(`Wrote ${outPath}`);
console.log(
  `users=${users.length} settings=${settings.length} scans=${scans.length} findings=${findings.length} ` +
  `jobs=${jobs.length} logFiles=${logFiles.length} logEntries=${logEntries.length} ` +
  `repos=${repos.length} githubScans=${githubScans.length} notifications=${notifications.length} ` +
  `apiKeys=${apiKeys.length} auditLogs=${auditLogs.length}`
);
