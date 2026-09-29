export interface AIProvider {
  name: string;
  type: string;
  initialize(config: Record<string, unknown>): Promise<void>;
  complete(request: AIRequest): Promise<AIResponse>;
  stream(request: AIRequest, onChunk: (chunk: string) => void): Promise<AIResponse>;
  getModels(): AIModel[];
  healthCheck(): Promise<boolean>;
}

export interface AIModel {
  id: string;
  name: string;
  maxTokens: number;
  supportsStreaming: boolean;
  supportsTools: boolean;
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

export interface AIToolCall {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
}

export interface AIResponse {
  content: string;
  toolCalls?: AIToolCall[];
  usage?: AIUsage;
  model: string;
  finishReason: 'stop' | 'length' | 'tool_calls' | 'error';
}

export interface AIUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
}

// Structured response types for specific tasks
export interface DockerfileFixResponse {
  fixedDockerfile: string;
  issues: DockerfileIssue[];
  changes: DiffChange[];
  securityImprovements: string[];
  explanation: string;
}

export interface DockerfileIssue {
  id: string;
  type: 'syntax' | 'security' | 'best_practice' | 'performance' | 'style';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  line: number;
  column?: number;
  message: string;
  rule: string;
  fixable: boolean;
  suggestion?: string;
}

export interface DiffChange {
  type: 'added' | 'removed' | 'modified';
  originalLine?: number;
  fixedLine?: number;
  originalContent: string;
  fixedContent: string;
  description?: string;
}

export interface KubernetesFixResponse {
  fixedYaml: string;
  issues: KubernetesIssue[];
  changes: DiffChange[];
  explanation: string;
}

export interface KubernetesIssue {
  id: string;
  resource: string;
  type: 'schema' | 'security' | 'best_practice' | 'performance' | 'reliability';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  path: string;
  message: string;
  rule: string;
  fixable: boolean;
  suggestion?: string;
}

export interface JenkinsfileFixResponse {
  fixedJenkinsfile: string;
  issues: JenkinsfileIssue[];
  changes: DiffChange[];
  explanation: string;
}

export interface JenkinsfileIssue {
  id: string;
  type: 'syntax' | 'security' | 'best_practice' | 'performance' | 'reliability';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  line: number;
  column?: number;
  message: string;
  rule: string;
  fixable: boolean;
  suggestion?: string;
}

export interface LogInvestigationResponse {
  rootCause: string;
  evidence: LogEvidence[];
  timeline: LogTimelineEvent[];
  affectedServices: string[];
  errorPatterns: LogErrorPattern[];
  recommendedActions: string[];
  confidence: number;
  analyzedEntries: number;
}

export interface LogEvidence {
  entry: LogEntry;
  relevance: number;
  explanation: string;
}

export interface LogEntry {
  id: string;
  timestamp: string;
  level: string;
  service?: string;
  message: string;
  raw: string;
  fields: Record<string, unknown>;
}

export interface LogTimelineEvent {
  timestamp: string;
  event: string;
  service?: string;
  severity: string;
  entries: LogEntry[];
}

export interface LogErrorPattern {
  pattern: string;
  count: number;
  firstSeen: string;
  lastSeen: string;
  examples: LogEntry[];
}

export interface DependencyFixResponse {
  explanation: string;
  targetVersion: string;
  breakingChanges: boolean;
  filesToChange: string[];
  upgradePath: string[];
  confidence: number;
}

export interface GitHubCodeFixResponse {
  patch: string;
  explanation: string;
  confidence: number;
  breakingChanges: string[];
}