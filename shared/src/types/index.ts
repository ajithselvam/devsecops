/**
 * Shared type definitions for the DevSecOps AI Platform
 */

// ============================================
// Common / Base Types
// ============================================

export type UUID = string & { readonly __brand: unique symbol };
export type ISODateString = string & { readonly __brand: unique symbol };

export interface BaseEntity {
  id: UUID;
  createdAt: ISODateString;
  updatedAt: ISODateString;
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

export type SortOrder = 'asc' | 'desc';

export interface SortOptions {
  field: string;
  order: SortOrder;
}

export interface FilterOptions {
  [key: string]: string | number | boolean | string[] | undefined;
}

// ============================================
// User & Auth Types
// ============================================

export interface User extends BaseEntity {
  email: string;
  name: string;
  avatarUrl?: string;
  role: UserRole;
  preferences: UserPreferences;
  lastLoginAt?: ISODateString;
}

export type UserRole = 'admin' | 'engineer' | 'viewer';

export interface UserPreferences {
  theme: 'light' | 'dark' | 'system';
  notifications: NotificationPreferences;
  sidebarCollapsed: boolean;
  language: string;
}

export interface NotificationPreferences {
  email: boolean;
  inApp: boolean;
  scanComplete: boolean;
  scanFailed: boolean;
  vulnerabilityFound: boolean;
  jobStatusChange: boolean;
}

export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface LoginCredentials {
  email: string;
  password: string;
  rememberMe?: boolean;
}

export interface RegisterData {
  email: string;
  password: string;
  name: string;
}

export interface JWTPayload {
  sub: UUID;
  email: string;
  role: UserRole;
  iat: number;
  exp: number;
}

// ============================================
// Job / Task Types
// ============================================

export type JobStatus =
  | 'queued'
  | 'running'
  | 'analyzing'
  | 'fixing'
  | 'completed'
  | 'failed'
  | 'cancelled';

export type JobType =
  | 'dockerfile_scan'
  | 'dockerfile_fix'
  | 'docker_image_scan'
  | 'docker_image_fix'
  | 'kubernetes_scan'
  | 'kubernetes_fix'
  | 'kubernetes_generate'
  | 'jenkinsfile_scan'
  | 'jenkinsfile_fix'
  | 'jenkinsfile_generate'
  | 'github_repo_scan'
  | 'github_dependency_scan'
  | 'github_secret_scan'
  | 'github_code_scan'
  | 'github_code_fix'
  | 'log_investigation'
  | 'log_search'
  | 'log_parse'
  | 'dependency_scan'
  | 'dependency_fix'
  | 'sbom_generation';

export interface Job extends BaseEntity {
  type: JobType;
  status: JobStatus;
  progress: number; // 0-100
  currentStep: string;
  totalSteps: number;
  input: Record<string, unknown>;
  output?: Record<string, unknown>;
  error?: string;
  startedAt?: ISODateString;
  completedAt?: ISODateString;
  userId: UUID;
  scanId?: UUID; // Link to scan record if applicable
}

export interface JobProgressUpdate {
  jobId: UUID;
  status: JobStatus;
  progress: number;
  currentStep: string;
  message?: string;
}

// ============================================
// Scan Types
// ============================================

export type ScanType =
  | 'dockerfile'
  | 'docker_image'
  | 'kubernetes'
  | 'jenkinsfile'
  | 'github_repo'
  | 'dependency'
  | 'logs';

export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';

export interface Scan extends BaseEntity {
  type: ScanType;
  status: ScanStatus;
  target: ScanTarget;
  summary: ScanSummary;
  findings: Finding[];
  userId: UUID;
  jobId?: UUID;
  completedAt?: ISODateString;
}

export interface ScanTarget {
  type: 'dockerfile' | 'docker_image' | 'kubernetes_yaml' | 'jenkinsfile' | 'github_repo' | 'dependency_file' | 'log_file';
  value: string; // file path, image name, repo URL, etc.
  metadata?: Record<string, unknown>;
}

export interface ScanSummary {
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  fixedCount: number;
  durationMs: number;
}

export interface Finding {
  id: UUID;
  scanId: UUID;
  type: FindingType;
  severity: Severity;
  title: string;
  description: string;
  file?: string;
  line?: number;
  column?: number;
  code?: string;
  ruleId?: string;
  ruleName?: string;
  cve?: string;
  package?: string;
  installedVersion?: string;
  fixedVersion?: string;
  cvssScore?: number;
  cwe?: string;
  references?: string[];
  remediation?: Remediation;
  status: FindingStatus;
  createdAt: ISODateString;
}

export type FindingType =
  | 'vulnerability'
  | 'misconfiguration'
  | 'secret'
  | 'bad_practice'
  | 'syntax_error'
  | 'security_issue'
  | 'performance'
  | 'compliance';

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type FindingStatus = 'open' | 'fixed' | 'ignored' | 'in_progress' | 'false_positive';

export interface Remediation {
  available: boolean;
  type: 'upgrade' | 'patch' | 'configuration' | 'removal' | 'replacement';
  description: string;
  steps: string[];
  breakingChanges?: string[];
  confidence: number; // 0-100
  fixedContent?: string;
  diff?: DiffResult;
}

// ============================================
// Diff Types
// ============================================

export interface DiffResult {
  original: string;
  fixed: string;
  changes: DiffChange[];
}

export interface DiffChange {
  type: 'added' | 'removed' | 'modified';
  originalLine?: number;
  fixedLine?: number;
  originalContent: string;
  fixedContent: string;
  description?: string;
}

// ============================================
// Dockerfile Types
// ============================================

export interface DockerfileAnalysis {
  dockerfile: string;
  issues: DockerfileIssue[];
  fixedDockerfile?: string;
  explanation?: string;
  securityImprovements?: string[];
  changes?: DiffChange[];
}

export interface DockerfileIssue {
  id: string;
  type: 'syntax' | 'security' | 'best_practice' | 'performance' | 'style';
  severity: Severity;
  line: number;
  column?: number;
  message: string;
  rule: string;
  fixable: boolean;
  suggestion?: string;
}

export interface DockerfileFixRequest {
  dockerfile: string;
  issues?: DockerfileIssue[];
  options?: DockerfileFixOptions;
}

export interface DockerfileFixOptions {
  fixSecurity?: boolean;
  fixBestPractices?: boolean;
  fixPerformance?: boolean;
  preserveComments?: boolean;
  baseImagePolicy?: 'latest' | 'pinned' | 'distroless' | 'alpine';
}

// ============================================
// Docker Image Types
// ============================================

export interface DockerImageScanResult {
  image: string;
  digest: string;
  os: string;
  architecture: string;
  packageCount: number;
  vulnerabilities: Vulnerability[];
  scanTime: ISODateString;
  scannerVersion: string;
}

export interface Vulnerability {
  id: string; // CVE ID
  package: string;
  installedVersion: string;
  fixedVersion?: string;
  severity: Severity;
  cvssScore?: number;
  cwe?: string;
  title: string;
  description: string;
  references: string[];
  type: 'os' | 'language' | 'config';
  fixAvailable: boolean;
}

export interface DockerImageFixRequest {
  image: string;
  vulnerabilities: Vulnerability[];
  dockerfile?: string;
  options?: DockerImageFixOptions;
}

export interface DockerImageFixOptions {
  strategy: 'update_packages' | 'change_base_image' | 'minimal';
  allowBreakingChanges?: boolean;
  targetBaseImage?: string;
}

export interface DockerImageFixResult {
  originalImage: string;
  fixedImage: string;
  fixedDockerfile: string;
  beforeVulnerabilities: Vulnerability[];
  afterVulnerabilities: Vulnerability[];
  buildLog: string;
  scanLog: string;
}

// ============================================
// Kubernetes Types
// ============================================

export interface KubernetesAnalysis {
  yaml: string;
  resources: K8sResource[];
  issues: KubernetesIssue[];
  fixedYaml?: string;
  explanation?: string;
  changes?: DiffChange[];
}

export interface K8sResource {
  kind: string;
  apiVersion: string;
  name: string;
  namespace?: string;
  valid: boolean;
  issues: KubernetesIssue[];
}

export interface KubernetesIssue {
  id: string;
  resource: string;
  type: 'schema' | 'security' | 'best_practice' | 'performance' | 'reliability';
  severity: Severity;
  path: string; // JSON path in the resource
  message: string;
  rule: string;
  fixable: boolean;
  suggestion?: string;
}

export interface KubernetesFixRequest {
  yaml: string;
  issues?: KubernetesIssue[];
  options?: KubernetesFixOptions;
}

export interface KubernetesFixOptions {
  fixSecurity?: boolean;
  fixBestPractices?: boolean;
  fixReliability?: boolean;
  addDefaults?: boolean;
}

export interface KubernetesGenerateRequest {
  resourceType: K8sResourceType;
  config: KubernetesGeneratorConfig;
}

export type K8sResourceType =
  | 'Deployment'
  | 'Service'
  | 'Ingress'
  | 'ConfigMap'
  | 'Secret'
  | 'StatefulSet'
  | 'DaemonSet'
  | 'Job'
  | 'CronJob'
  | 'Namespace'
  | 'ServiceAccount'
  | 'Role'
  | 'RoleBinding'
  | 'NetworkPolicy'
  | 'PersistentVolumeClaim';

export interface KubernetesGeneratorConfig {
  name: string;
  namespace?: string;
  image: string;
  replicas?: number;
  port?: number;
  serviceType?: 'ClusterIP' | 'NodePort' | 'LoadBalancer';
  ingressEnabled?: boolean;
  ingressHost?: string;
  cpuRequest?: string;
  memoryRequest?: string;
  cpuLimit?: string;
  memoryLimit?: string;
  livenessProbe?: ProbeConfig;
  readinessProbe?: ProbeConfig;
  securityContext?: SecurityContextConfig;
  envVars?: Record<string, string>;
  volumes?: VolumeConfig[];
}

export interface ProbeConfig {
  enabled: boolean;
  path?: string;
  port?: number;
  initialDelaySeconds?: number;
  periodSeconds?: number;
}

export interface SecurityContextConfig {
  enabled: boolean;
  runAsNonRoot?: boolean;
  runAsUser?: number;
  readOnlyRootFilesystem?: boolean;
  allowPrivilegeEscalation?: boolean;
  capabilities?: string[];
}

export interface VolumeConfig {
  name: string;
  type: 'emptyDir' | 'configMap' | 'secret' | 'persistentVolumeClaim';
  config?: Record<string, unknown>;
}

// ============================================
// Jenkins Types
// ============================================

export interface JenkinsfileAnalysis {
  jenkinsfile: string;
  issues: JenkinsfileIssue[];
  fixedJenkinsfile?: string;
  explanation?: string;
  changes?: DiffChange[];
}

export interface JenkinsfileIssue {
  id: string;
  type: 'syntax' | 'security' | 'best_practice' | 'performance' | 'reliability';
  severity: Severity;
  line: number;
  column?: number;
  message: string;
  rule: string;
  fixable: boolean;
  suggestion?: string;
}

export interface JenkinsfileFixRequest {
  jenkinsfile: string;
  issues?: JenkinsfileIssue[];
  options?: JenkinsfileFixOptions;
}

export interface JenkinsfileFixOptions {
  fixSecurity?: boolean;
  fixBestPractices?: boolean;
  fixPerformance?: boolean;
  addErrorHandling?: boolean;
}

export interface JenkinsfileGenerateRequest {
  config: JenkinsGeneratorConfig;
}

export interface JenkinsGeneratorConfig {
  application: 'nodejs' | 'python' | 'java' | 'go' | 'docker' | 'generic';
  repositoryUrl: string;
  buildTool: 'npm' | 'maven' | 'gradle' | 'pip' | 'make' | 'none';
  testing: boolean;
  dockerBuild: boolean;
  securityScan: boolean;
  dockerPush: boolean;
  deployment: 'kubernetes' | 'vm' | 'none' | 'ecs' | 'cloudrun';
  environments: ('dev' | 'staging' | 'production')[];
  registryUrl?: string;
  kubernetesConfig?: KubernetesGeneratorConfig;
}

export interface JenkinsServer {
  id: UUID;
  name: string;
  url: string;
  credentialsId: UUID; // References encrypted credentials
  connected: boolean;
  lastTestedAt?: ISODateString;
  version?: string;
}

export interface JenkinsJob {
  name: string;
  url: string;
  color: string; // Jenkins color: blue, red, yellow, disabled, etc.
  lastBuild?: JenkinsBuild;
  nextBuildNumber: number;
}

export interface JenkinsBuild {
  number: number;
  url: string;
  status: 'success' | 'failure' | 'unstable' | 'aborted' | 'building';
  timestamp: ISODateString;
  duration: number;
  log?: string;
}

// ============================================
// GitHub Types
// ============================================

export interface GitHubRepository {
  id: UUID;
  userId: UUID;
  githubId: number;
  name: string;
  fullName: string;
  url: string;
  cloneUrl: string;
  defaultBranch: string;
  private: boolean;
  connectedAt: ISODateString;
  lastScannedAt?: ISODateString;
}

export interface GitHubScanResult {
  repository: GitHubRepository;
  branch: string;
  commitSha: string;
  sbom: SBOM;
  vulnerabilities: Vulnerability[];
  secrets: SecretFinding[];
  codeIssues: CodeIssue[];
  dependencyIssues: DependencyIssue[];
  summary: ScanSummary;
  scanTime: ISODateString;
}

export interface SBOM {
  packages: SBOMPackage[];
  relationships: SBOMRelationship[];
  metadata: SBOMMetadata;
}

export interface SBOMPackage {
  name: string;
  version: string;
  type: 'npm' | 'pypi' | 'maven' | 'go' | 'nuget' | 'gem' | 'composer' | 'cargo' | 'system';
  license?: string;
  purl: string;
  location?: string;
  dependencies?: string[];
}

export interface SBOMRelationship {
  parent: string; // purl
  child: string; // purl
  type: 'depends-on';
}

export interface SBOMMetadata {
  tool: string;
  version: string;
  timestamp: ISODateString;
}

export interface SecretFinding {
  id: string;
  type: string; // e.g., 'aws_access_key', 'github_token', 'private_key'
  file: string;
  line: number;
  column?: number;
  severity: Severity;
  rule: string;
  entropy?: number;
  match?: string;
  verified: boolean;
}

export interface CodeIssue {
  id: string;
  file: string;
  line: number;
  column?: number;
  severity: Severity;
  rule: string;
  ruleName: string;
  message: string;
  code: string;
  category: 'security' | 'bug' | 'performance' | 'style' | 'maintainability';
  cwe?: string;
  fixable: boolean;
  suggestion?: string;
}

export interface DependencyIssue {
  package: string;
  currentVersion: string;
  latestVersion: string;
  vulnerabilities: Vulnerability[];
  outdated: boolean;
  licenseRisk?: 'none' | 'low' | 'medium' | 'high';
}

export interface GitHubFixRequest {
  findingId: string;
  repositoryId: UUID;
  branch: string;
  fixType: 'patch' | 'upgrade' | 'removal' | 'replacement';
}

export interface GitHubFixResult {
  branchName: string;
  commitSha: string;
  prUrl?: string;
  filesChanged: string[];
  testsPassed: boolean;
  scanPassed: boolean;
}

// ============================================
// Log Investigation Types
// ============================================

export interface LogFile {
  id: UUID;
  name: string;
  size: number;
  lineCount: number;
  format: LogFormat;
  uploadedAt: ISODateString;
  indexed: boolean;
  userId: UUID;
}

export type LogFormat = 'json' | 'text' | 'syslog' | 'nginx' | 'apache' | 'custom';

export interface LogEntry {
  id: UUID;
  logFileId: UUID;
  timestamp: ISODateString;
  level: LogLevel;
  service?: string;
  message: string;
  raw: string;
  fields: Record<string, unknown>;
  indexed: boolean;
}

export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'fatal' | 'trace';

export interface LogSearchQuery {
  query: string;
  logFileIds: UUID[];
  timeRange?: TimeRange;
  level?: LogLevel[];
  service?: string[];
  limit?: number;
  offset?: number;
}

export interface TimeRange {
  start: ISODateString;
  end: ISODateString;
}

export interface LogSearchResult {
  entries: LogEntry[];
  total: number;
  facets: LogFacets;
}

export interface LogFacets {
  levels: Record<LogLevel, number>;
  services: Record<string, number>;
  timeDistribution: TimeBucket[];
}

export interface TimeBucket {
  timestamp: ISODateString;
  count: number;
}

export interface LogInvestigationRequest {
  question: string;
  logFileIds: UUID[];
  timeRange?: TimeRange;
  context?: Record<string, unknown>;
}

export interface LogInvestigationResult {
  question: string;
  rootCause: string;
  evidence: LogEvidence[];
  timeline: LogTimelineEvent[];
  affectedServices: string[];
  errorPatterns: LogErrorPattern[];
  recommendedActions: string[];
  confidence: number; // 0-100
  analyzedEntries: number;
  analysisTime: ISODateString;
}

export interface LogEvidence {
  entry: LogEntry;
  relevance: number; // 0-100
  explanation: string;
}

export interface LogTimelineEvent {
  timestamp: ISODateString;
  event: string;
  service?: string;
  severity: LogLevel;
  entries: LogEntry[];
}

export interface LogErrorPattern {
  pattern: string;
  count: number;
  firstSeen: ISODateString;
  lastSeen: ISODateString;
  examples: LogEntry[];
}

// ============================================
// Dependency Types
// ============================================

export interface DependencyScanResult {
  repositoryUrl: string;
  manifests: DependencyManifest[];
  sbom: SBOM;
  vulnerabilities: Vulnerability[];
  outdated: OutdatedDependency[];
  summary: DependencySummary;
  scanTime: ISODateString;
}

export interface DependencyManifest {
  path: string;
  type: 'package.json' | 'requirements.txt' | 'poetry.lock' | 'pom.xml' | 'build.gradle' | 'go.mod' | 'go.sum' | 'Gemfile' | 'Gemfile.lock' | 'composer.json' | 'cargo.toml' | 'cargo.lock';
  dependencies: Dependency[];
  devDependencies?: Dependency[];
}

export interface Dependency {
  name: string;
  version: string;
  type: 'runtime' | 'development' | 'peer' | 'optional';
  license?: string;
  repository?: string;
  purl?: string;
}

export interface OutdatedDependency {
  name: string;
  currentVersion: string;
  latestVersion: string;
  type: 'major' | 'minor' | 'patch';
  breakingChanges: boolean;
  releaseDate?: ISODateString;
  changelogUrl?: string;
}

export interface DependencySummary {
  totalDependencies: number;
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  outdated: number;
  deprecated: number;
  licenseIssues: number;
}

export interface DependencyFixRequest {
  package: string;
  currentVersion: string;
  targetVersion: string;
  manifestPath: string;
  vulnerabilityIds?: string[];
}

export interface DependencyFixResult {
  success: boolean;
  updatedManifest: string;
  changes: DiffChange[];
  testsPassed?: boolean;
  scanPassed?: boolean;
  branchName?: string;
  prUrl?: string;
}

export interface DependencyNode {
  name: string;
  version: string;
  type: 'runtime' | 'development' | 'peer' | 'optional' | 'direct' | 'transitive';
  license?: string;
  repository?: string;
  purl?: string;
  latestVersion?: string;
  vulnerabilities: Vulnerability[];
}

export interface DependencyScan extends BaseEntity {
  name: string;
  repositoryUrl?: string;
  branch?: string;
  manifestPath?: string;
  dependencies: DependencyNode[];
  sbom: SBOM;
  vulnerabilities: Vulnerability[];
  outdated: OutdatedDependency[];
  summary: DependencySummary;
  healthScore: number;
}

export interface DependencyRemediation {
  dependencyName: string;
  currentVersion: string;
  recommendedVersion: string;
  explanation: string;
  steps: string[];
  command: string;
  risks: string[];
  confidence: number;
  breakingChanges: boolean;
}

export type SBOMFormat = 'cyclonedx' | 'spdx' | 'syft';

// ============================================
// AI Types
// ============================================

export type AIProviderType = 'apps_script' | 'openai' | 'gemini' | 'anthropic' | 'custom' | 'omniroute' | 'freeai';

export interface AIProviderConfig {
  type: AIProviderType;
  name: string;
  enabled: boolean;
  config: Record<string, unknown>;
  models: AIModel[];
  defaultModel: string;
}

export interface AIModel {
  id: string;
  name: string;
  maxTokens: number;
  supportsStreaming: boolean;
  supportsTools: boolean;
  costPer1kInputTokens?: number;
  costPer1kOutputTokens?: number;
}

export interface AIRequest {
  prompt: string;
  systemPrompt?: string;
  model?: string;
  temperature?: number;
  maxTokens?: number;
  tools?: AITool[];
  context?: Record<string, unknown>;
  stream?: boolean;
}

export interface AITool {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
}

export interface AIResponse {
  content: string;
  toolCalls?: AIToolCall[];
  usage?: AIUsage;
  model: string;
  finishReason: 'stop' | 'length' | 'tool_calls' | 'error';
}

export interface AIToolCall {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
}

export interface AIUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
}

// ============================================
// Notification Types
// ============================================

export interface Notification extends BaseEntity {
  userId: UUID;
  type: NotificationType;
  title: string;
  message: string;
  read: boolean;
  actionUrl?: string;
  metadata?: Record<string, unknown>;
}

export type NotificationType =
  | 'scan_complete'
  | 'scan_failed'
  | 'vulnerability_found'
  | 'job_completed'
  | 'job_failed'
  | 'fix_ready'
  | 'pr_created'
  | 'system_alert'
  | 'info';

// ============================================
// Settings Types
// ============================================

export interface AppSettings {
  ai: AISettings;
  docker: DockerSettings;
  github: GitHubSettings;
  jenkins: JenkinsSettings;
  scanning: ScanningSettings;
  notifications: NotificationSettings;
  security: SecuritySettings;
}

export interface AISettings {
  provider: AIProviderType;
  appsScriptUrl?: string;
  openaiApiKey?: string;
  geminiApiKey?: string;
  anthropicApiKey?: string;
  defaultModel: string;
  temperature: number;
  maxTokens: number;
}

export interface DockerSettings {
  dockerHubUsername?: string;
  dockerHubToken?: string; // Encrypted
  defaultRegistry: string;
  buildTimeout: number;
  scanTimeout: number;
}

export interface GitHubSettings {
  appId?: string;
  privateKey?: string; // Encrypted
  webhookSecret?: string; // Encrypted
  defaultOrg?: string;
}

export interface JenkinsSettings {
  servers: JenkinsServer[];
  defaultServerId?: UUID;
}

export interface ScanningSettings {
  defaultTools: string[];
  grypeConfig?: GrypeConfig;
  trivyConfig?: TrivyConfig;
  semgrepConfig?: SemgrepConfig;
  gitleaksConfig?: GitleaksConfig;
  maxConcurrentScans: number;
  scanTimeout: number;
}

export interface GrypeConfig {
  dbUpdateInterval: number;
  vulnerabilitySources: string[];
}

export interface TrivyConfig {
  dbRepository: string;
  skipDbUpdate: boolean;
  severity: Severity[];
}

export interface SemgrepConfig {
  config: string; // 'auto' or path to config
  rules?: string[];
}

export interface GitleaksConfig {
  configPath?: string;
  verbose: boolean;
}

export interface NotificationSettings {
  emailEnabled: boolean;
  smtpHost?: string;
  smtpPort?: number;
  smtpUser?: string;
  smtpPassword?: string; // Encrypted
  fromEmail?: string;
}

export interface SecuritySettings {
  sessionTimeout: number;
  maxLoginAttempts: number;
  lockoutDuration: number;
  passwordMinLength: number;
  requireMfa: boolean;
  allowedOrigins: string[];
}

// ============================================
// API Response Types
// ============================================

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: ApiError;
  meta?: Record<string, unknown>;
}

export interface ApiError {
  code: string;
  message: string;
  details?: Record<string, unknown>;
  statusCode: number;
}

export interface ApiListResponse<T> extends ApiResponse<PaginatedResponse<T>> {}

// ============================================
// WebSocket Types
// ============================================

export interface WSMessage<T = unknown> {
  type: string;
  payload: T;
  timestamp: ISODateString;
}

export type WSJobUpdate = WSMessage<JobProgressUpdate>;
export type WSNotification = WSMessage<Notification>;
export type WSScanUpdate = WSMessage<{ scanId: UUID; status: ScanStatus; progress: number }>;