/**
 * Row shapes returned by the data layer.
 *
 * These mirror the legacy Prisma models (camelCase, `Date` for timestamps,
 * JSON held as strings) because the route handlers, the WebSocket payloads and
 * the React frontend all speak that contract. `passwordHash` is gone: passwords
 * now live in InsForge auth, never in the application database.
 */

export interface User {
  id: string;
  email: string;
  name: string;
  avatarUrl: string | null;
  role: string;
  theme: string;
  sidebarCollapsed: boolean;
  language: string;
  emailNotifications: boolean;
  inAppNotifications: boolean;
  notifyScanComplete: boolean;
  notifyScanFailed: boolean;
  notifyVulnFound: boolean;
  notifyJobChange: boolean;
  lastLoginAt: Date | string | null;
  createdAt: Date | string;
  updatedAt: Date | string;
  settings?: Settings | null;
}

export interface Settings {
  id: string;
  userId: string;
  aiProvider: string;
  aiAppsScriptUrl: string | null;
  aiOpenaiKey: string | null;
  aiGeminiKey: string | null;
  aiAnthropicKey: string | null;
  aiDefaultModel: string;
  aiTemperature: number;
  aiMaxTokens: number;
  dockerHubUsername: string | null;
  dockerHubToken: string | null;
  dockerRegistry: string;
  dockerBuildTimeout: number;
  dockerScanTimeout: number;
  githubAppId: string | null;
  githubPrivateKey: string | null;
  githubWebhookSecret: string | null;
  githubDefaultOrg: string | null;
  githubToken: string | null;
  gitlabToken: string | null;
  bitbucketToken: string | null;
  slackWebhook: string | null;
  teamsWebhook: string | null;
  jiraUrl: string | null;
  jiraToken: string | null;
  webhookUrl: string | null;
  webhookSecret: string | null;
  scanningDefaultTools: string;
  scanningMaxConcurrent: number;
  scanningTimeout: number;
  debugMode: boolean;
  telemetryEnabled: boolean;
  autoUpdate: boolean;
  createdAt: Date | string;
  updatedAt: Date | string;
}

export interface Scan {
  id: string;
  userId: string;
  type: string;
  status: string;
  targetType: string;
  targetValue: string;
  targetMeta: string | null;
  summary: string | null;
  jobId: string | null;
  artifactKey: string | null;
  artifactUrl: string | null;
  completedAt: Date | string | null;
  createdAt: Date | string;
  updatedAt: Date | string;
  findings?: Finding[];
}

export interface Finding {
  id: string;
  scanId: string;
  type: string;
  severity: string;
  title: string;
  description: string;
  file: string | null;
  line: number | null;
  column: number | null;
  code: string | null;
  ruleId: string | null;
  ruleName: string | null;
  cve: string | null;
  package: string | null;
  installedVersion: string | null;
  fixedVersion: string | null;
  cvssScore: number | null;
  cwe: string | null;
  references: string;
  remediation: string | null;
  status: string;
  createdAt: Date | string;
  updatedAt: Date | string;
  scan?: Scan | null;
}

export interface Job {
  id: string;
  userId: string;
  type: string;
  status: string;
  progress: number;
  currentStep: string;
  totalSteps: number;
  input: string;
  output: string | null;
  error: string | null;
  scanId: string | null;
  startedAt: Date | string | null;
  completedAt: Date | string | null;
  createdAt: Date | string;
  updatedAt: Date | string;
}

export interface LogFile {
  id: string;
  userId: string;
  name: string;
  size: number | string;
  lineCount: number;
  format: string;
  indexed: boolean;
  storageKey: string | null;
  storageUrl: string | null;
  createdAt: Date | string;
  updatedAt: Date | string;
  entries?: LogEntry[];
}

export interface LogEntry {
  id: string;
  logFileId: string;
  timestamp: Date | string;
  level: string;
  service: string | null;
  message: string;
  raw: string;
  fields: string;
  indexed: boolean;
  createdAt: Date | string;
}

export interface GitHubRepository {
  id: string;
  userId: string;
  githubId: number | string;
  name: string;
  fullName: string;
  url: string;
  cloneUrl: string;
  defaultBranch: string;
  private: boolean;
  connectedAt: Date | string;
  lastScannedAt: Date | string | null;
  createdAt: Date | string;
  updatedAt: Date | string;
  scans?: GitHubScan[];
}

export interface GitHubScan {
  id: string;
  repoId: string;
  branch: string;
  commitSha: string;
  sbom: string | null;
  summary: string | null;
  vulnerabilities: string;
  secrets: string;
  codeIssues: string;
  depIssues: string;
  scanTime: Date | string;
  createdAt: Date | string;
}

export interface Notification {
  id: string;
  userId: string;
  type: string;
  title: string;
  message: string;
  read: boolean;
  actionUrl: string | null;
  metadata: string | null;
  createdAt: Date | string;
  updatedAt: Date | string;
}

export interface ApiKey {
  id: string;
  userId: string;
  name: string;
  keyHash: string;
  prefix: string;
  lastUsedAt: Date | string | null;
  expiresAt: Date | string | null;
  revokedAt: Date | string | null;
  createdAt: Date | string;
  updatedAt: Date | string;
}

export interface AuditLog {
  id: string;
  userId: string | null;
  action: string;
  resource: string;
  resourceId: string | null;
  metadata: string | null;
  ip: string | null;
  userAgent: string | null;
  createdAt: Date | string;
}
