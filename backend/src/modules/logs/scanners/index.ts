import { execFileSync } from 'child_process';
import { writeFileSync, rmSync, mkdtempSync, readFileSync, statSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
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
  context: { before: string[]; after: string[] };
  file: string;
}

export interface ScanProgress {
  progress: number;
  currentStep: string;
}

async function updateProgress(job: Job, progress: ScanProgress): Promise<void> {
  await job.updateProgress(progress);
}

export async function investigateLogs(
  question: string,
  logEntries: any[],
  context: any,
  job: Job
): Promise<LogInvestigationResult> {
  await updateProgress(job, { progress: 10, currentStep: 'Loading and parsing log entries' });

  // Parse and normalize log entries
  const normalizedEntries = normalizeLogEntries(logEntries);

  await updateProgress(job, { progress: 25, currentStep: 'Analyzing log patterns' });

  // Extract patterns and anomalies
  const patterns = extractPatterns(normalizedEntries);
  const anomalies = detectAnomalies(normalizedEntries);

  await updateProgress(job, { progress: 50, currentStep: 'Building timeline' });

  // Build timeline of events
  const timeline = buildTimeline(normalizedEntries, anomalies);

  await updateProgress(job, { progress: 70, currentStep: 'Identifying root cause' });

  // Identify root cause based on question and patterns
  const { rootCause, evidence, recommendations } = await identifyRootCause(
    question,
    normalizedEntries,
    patterns,
    anomalies,
    timeline,
    context
  );

  await updateProgress(job, { progress: 90, currentStep: 'Generating report' });

  await updateProgress(job, { progress: 100, currentStep: 'Investigation completed' });

  return {
    rootCause,
    evidence,
    timeline,
    recommendations,
    relatedPatterns: patterns
  };
}

export async function searchLogs(
  query: string,
  logFiles: string[],
  options: { caseSensitive?: boolean; regex?: boolean; before?: number; after?: number } = {},
  job: Job
): Promise<LogSearchResult> {
  await updateProgress(job, { progress: 10, currentStep: 'Searching log files' });

  const matches: LogMatch[] = [];
  let scannedLines = 0;

  const regex = options.regex ? new RegExp(query, options.caseSensitive ? 'g' : 'gi') : null;
  const searchTerm = options.regex ? null : query.toLowerCase();

  for (const file of logFiles) {
    try {
      const content = readFileSync(file, 'utf-8');
      const lines = content.split('\n');

      for (let i = 0; i < lines.length; i++) {
        scannedLines++;
        const line = lines[i];
        const lowerLine = line.toLowerCase();

        let matched = false;
        if (regex) {
          matched = regex.test(line);
        } else if (searchTerm && lowerLine.includes(searchTerm)) {
          matched = true;
        }

        if (matched) {
          const before = lines.slice(Math.max(0, i - (options.before || 5)), i);
          const after = lines.slice(i + 1, i + 1 + (options.after || 5));

          matches.push({
            lineNumber: i + 1,
            message: line,
            context: { before, after },
            file
          });
        }
      }
    } catch (error) {
      console.warn(`Failed to search file ${file}:`, error);
    }
  }

  await updateProgress(job, { progress: 100, currentStep: 'Search completed' });

  return { matches, totalMatches: matches.length, scannedLines };
}

function normalizeLogEntries(entries: any[]): LogLine[] {
  return entries.map((entry, index) => ({
    lineNumber: index + 1,
    timestamp: entry.timestamp || entry.time || entry['@timestamp'],
    level: entry.level || entry.severity || entry.priority,
    message: entry.message || entry.msg || entry.log || JSON.stringify(entry),
    raw: typeof entry === 'string' ? entry : JSON.stringify(entry)
  }));
}

function extractPatterns(entries: LogLine[]): LogPattern[] {
  const patterns: Map<string, LogPattern> = new Map();

  // Common error patterns
  const errorPatterns = [
    { pattern: /error|exception|fail|fatal|panic/i, description: 'Error or exception detected', severity: 'high' as const },
    { pattern: /timeout|timed out|connection refused|connection reset/i, description: 'Timeout or connection issue', severity: 'high' as const },
    { pattern: /out of memory|OOM|memory limit|heap space/i, description: 'Memory issue', severity: 'critical' as const },
    { pattern: /disk full|no space left|disk quota/i, description: 'Disk space issue', severity: 'critical' as const },
    { pattern: /permission denied|access denied|unauthorized|forbidden/i, description: 'Permission issue', severity: 'high' as const },
    { pattern: /null pointer|nil pointer|undefined|segmentation fault/i, description: 'Null pointer or segmentation fault', severity: 'critical' as const },
    { pattern: /deadlock|lock wait|lock timeout/i, description: 'Lock contention', severity: 'high' as const },
    { pattern: /retry|retrying|backoff/i, description: 'Retry logic triggered', severity: 'medium' as const },
    { pattern: /deprecated|deprecation/i, description: 'Deprecated API usage', severity: 'low' as const },
    { pattern: /warn|warning/i, description: 'Warning message', severity: 'medium' as const },
  ];

  for (const entry of entries) {
    for (const { pattern, description, severity } of errorPatterns) {
      if (pattern.test(entry.message)) {
        const key = description;
        if (!patterns.has(key)) {
          patterns.set(key, { pattern: pattern.source, description, count: 0, severity, examples: [] });
        }
        const p = patterns.get(key)!;
        p.count++;
        if (p.examples.length < 3) {
          p.examples.push(entry.message.substring(0, 200));
        }
      }
    }
  }

  return Array.from(patterns.values()).sort((a, b) => b.count - a.count);
}

function detectAnomalies(entries: LogLine[]): LogLine[] {
  const anomalies: LogLine[] = [];

  // Look for sudden spikes in error rates
  const windowSize = 100;
  const errorLevels = ['error', 'fatal', 'critical', 'panic'];

  for (let i = 0; i < entries.length; i += windowSize) {
    const window = entries.slice(i, i + windowSize);
    const errorCount = window.filter(e => errorLevels.includes((e.level || '').toLowerCase())).length;

    if (errorCount > windowSize * 0.1) { // More than 10% errors
      anomalies.push(...window.filter(e => errorLevels.includes((e.level || '').toLowerCase())));
    }
  }

  // Look for repeated identical messages (possible loops)
  const messageCounts = new Map<string, number>();
  for (const entry of entries) {
    const key = entry.message.substring(0, 100);
    messageCounts.set(key, (messageCounts.get(key) || 0) + 1);
  }

  for (const [message, count] of messageCounts) {
    if (count > 10) {
      const entriesWithMessage = entries.filter(e => e.message.substring(0, 100) === message);
      anomalies.push(...entriesWithMessage.slice(0, 5));
    }
  }

  return anomalies;
}

function buildTimeline(entries: LogLine[], anomalies: LogLine[]): LogTimelineEvent[] {
  const timeline: LogTimelineEvent[] = [];

  // Group entries by time periods
  const timeGroups = new Map<string, LogLine[]>();

  for (const entry of entries) {
    if (entry.timestamp) {
      // Group by minute
      const timeKey = entry.timestamp.substring(0, 16); // YYYY-MM-DDTHH:MM
      if (!timeGroups.has(timeKey)) {
        timeGroups.set(timeKey, []);
      }
      timeGroups.get(timeKey)!.push(entry);
    }
  }

  for (const [timeKey, groupEntries] of timeGroups) {
    const errorCount = groupEntries.filter(e => ['error', 'fatal', 'critical'].includes((e.level || '').toLowerCase())).length;
    const warnCount = groupEntries.filter(e => ['warn', 'warning'].includes((e.level || '').toLowerCase())).length;

    if (errorCount > 0 || warnCount > 5) {
      timeline.push({
        timestamp: timeKey,
        event: `${errorCount} errors, ${warnCount} warnings in this period`,
        severity: errorCount > 0 ? 'high' : warnCount > 10 ? 'medium' : 'low',
        source: 'log-analysis',
        relatedLines: groupEntries.map(e => e.lineNumber)
      });
    }
  }

  // Add anomaly events
  for (const anomaly of anomalies) {
    if (anomaly.timestamp) {
      timeline.push({
        timestamp: anomaly.timestamp,
        event: `Anomaly detected: ${anomaly.message.substring(0, 100)}`,
        severity: 'high',
        source: 'anomaly-detection',
        relatedLines: [anomaly.lineNumber]
      });
    }
  }

  return timeline.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
}

async function identifyRootCause(
  question: string,
  entries: LogLine[],
  patterns: LogPattern[],
  anomalies: LogLine[],
  timeline: LogTimelineEvent[],
  context: any
): Promise<{ rootCause: string; evidence: LogEvidence[]; recommendations: string[] }> {
  // This would ideally use AI to analyze the question and logs
  // For now, implement rule-based analysis

  const evidence: LogEvidence[] = [];
  const recommendations: string[] = [];

  // Group anomalies by type
  const anomaliesByType = new Map<string, LogLine[]>();
  for (const anomaly of anomalies) {
    const type = categorizeAnomaly(anomaly);
    if (!anomaliesByType.has(type)) {
      anomaliesByType.set(type, []);
    }
    anomaliesByType.get(type)!.push(anomaly);
  }

  // Create evidence from anomaly groups
  for (const [type, typeAnomalies] of anomaliesByType) {
    evidence.push({
      id: `evidence-${type}`,
      type: type as any,
      severity: typeAnomalies.some(a => ['error', 'fatal', 'critical'].includes((a.level || '').toLowerCase())) ? 'critical' : 'high',
      description: `${typeAnomalies.length} ${type} events detected`,
      logLines: typeAnomalies.slice(0, 10),
      timestamp: typeAnomalies[0]?.timestamp,
      source: 'anomaly-detection'
    });
  }

  // Create evidence from top patterns
  for (const pattern of patterns.slice(0, 5)) {
    if (pattern.severity === 'critical' || pattern.severity === 'high') {
      evidence.push({
        id: `evidence-pattern-${pattern.description}`,
        type: 'error',
        severity: pattern.severity,
        description: `${pattern.description} (${pattern.count} occurrences)`,
        logLines: [],
        source: 'pattern-analysis'
      });
    }
  }

  // Determine root cause based on question and evidence
  let rootCause = 'Unable to determine root cause from available logs. ';

  if (evidence.length > 0) {
    const criticalEvidence = evidence.filter(e => e.severity === 'critical');
    const highEvidence = evidence.filter(e => e.severity === 'high');

    if (criticalEvidence.length > 0) {
      rootCause = `Primary root cause appears to be: ${criticalEvidence[0].description}. `;
    } else if (highEvidence.length > 0) {
      rootCause = `Likely root cause: ${highEvidence[0].description}. `;
    }

    rootCause += `Found ${evidence.length} significant evidence points. `;
  }

  // Add pattern-based root cause hints
  const topPattern = patterns[0];
  if (topPattern && topPattern.count > 5) {
    rootCause += `Most frequent pattern: ${topPattern.description} (${topPattern.count} times). `;
  }

  // Generate recommendations based on findings
  for (const ev of evidence) {
    switch (ev.type) {
      case 'error':
      case 'exception':
        recommendations.push('Investigate the stack traces and error messages in the identified log lines');
        recommendations.push('Check application dependencies and recent deployments');
        break;
      case 'timeout':
      case 'network':
        recommendations.push('Check network connectivity and service availability');
        recommendations.push('Review timeout configurations and consider increasing limits');
        break;
      case 'resource':
        recommendations.push('Monitor system resources (CPU, memory, disk, network)');
        recommendations.push('Consider scaling resources or optimizing resource usage');
        break;
      case 'config':
        recommendations.push('Review configuration changes and validate config files');
        recommendations.push('Check for missing or incorrect environment variables');
        break;
      case 'security':
        recommendations.push('Investigate potential security incidents immediately');
        recommendations.push('Review access logs and authentication events');
        break;
    }
  }

  // Add general recommendations
  if (patterns.some(p => p.description.includes('retry'))) {
    recommendations.push('Investigate why retries are occurring - may indicate upstream service issues');
  }
  if (patterns.some(p => p.description.includes('deprecated'))) {
    recommendations.push('Plan migration away from deprecated APIs');
  }

  return { rootCause, evidence, recommendations: [...new Set(recommendations)] };
}

function categorizeAnomaly(entry: LogLine): string {
  const msg = entry.message.toLowerCase();
  if (msg.includes('timeout') || msg.includes('connection refused') || msg.includes('connection reset')) return 'network';
  if (msg.includes('memory') || msg.includes('oom') || msg.includes('disk') || msg.includes('space')) return 'resource';
  if (msg.includes('permission') || msg.includes('unauthorized') || msg.includes('forbidden') || msg.includes('access denied')) return 'security';
  if (msg.includes('config') || msg.includes('setting') || msg.includes('parameter')) return 'config';
  if (msg.includes('exception') || msg.includes('panic') || msg.includes('fatal') || msg.includes('segmentation')) return 'exception';
  return 'error';
}

export async function parseLogFile(
  filePath: string,
  job: Job
): Promise<any[]> {
  await updateProgress(job, { progress: 10, currentStep: 'Reading log file' });

  const content = readFileSync(filePath, 'utf-8');
  const lines = content.split('\n');

  await updateProgress(job, { progress: 50, currentStep: 'Parsing log lines' });

  const entries = lines.map((line, index) => parseLogLine(line, index + 1)).filter(Boolean);

  await updateProgress(job, { progress: 100, currentStep: 'Parsing completed' });

  return entries;
}

function parseLogLine(line: string, lineNumber: number): any | null {
  if (!line.trim()) return null;

  // Try to parse as JSON first
  try {
    const parsed = JSON.parse(line);
    if (parsed.message || parsed.msg || parsed.log || parsed['@timestamp']) {
      return {
        lineNumber,
        timestamp: parsed['@timestamp'] || parsed.timestamp || parsed.time,
        level: parsed.level || parsed.severity || parsed.priority,
        message: parsed.message || parsed.msg || parsed.log,
        raw: line,
        ...parsed
      };
    }
  } catch {
    // Not JSON, try common log formats
  }

  // Common log format patterns
  const patterns = [
    // Syslog: Jan  1 12:00:00 hostname app[123]: message
    /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.+)$/,
    // ISO timestamp: 2024-01-01T12:00:00.000Z [INFO] message
    /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s*\[(\w+)\]\s*(.+)$/,
    // Simple: 2024-01-01 12:00:00 INFO message
    /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(.+)$/,
    // Log4j: 2024-01-01 12:00:00,000 INFO [thread] class - message
    /^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3})\s+(\w+)\s+\[.+?\]\s+\S+\s+-\s+(.+)$/
  ];

  for (const pattern of patterns) {
    const match = line.match(pattern);
    if (match) {
      return {
        lineNumber,
        timestamp: match[1],
        level: match[2],
        message: match[3],
        raw: line
      };
    }
  }

  // Fallback: treat entire line as message
  return {
    lineNumber,
    message: line,
    raw: line
  };
}

export async function getLogStats(
  logFiles: string[],
  job: Job
): Promise<{
  totalLines: number;
  totalFiles: number;
  totalSize: number;
  levelDistribution: Record<string, number>;
  timeRange: { start: string; end: string } | null;
}> {
  await updateProgress(job, { progress: 10, currentStep: 'Analyzing log files' });

  let totalLines = 0;
  let totalSize = 0;
  const levelDistribution: Record<string, number> = {};
  let startTime: string | null = null;
  let endTime: string | null = null;

  for (const file of logFiles) {
    try {
      const stats = statSync(file);
      totalSize += stats.size;

      const content = readFileSync(file, 'utf-8');
      const lines = content.split('\n');

      for (const line of lines) {
        if (!line.trim()) continue;
        totalLines++;

        const parsed = parseLogLine(line, 0);
        if (parsed?.level) {
          const level = parsed.level.toLowerCase();
          levelDistribution[level] = (levelDistribution[level] || 0) + 1;
        }

        if (parsed?.timestamp) {
          if (!startTime || parsed.timestamp < startTime) startTime = parsed.timestamp;
          if (!endTime || parsed.timestamp > endTime) endTime = parsed.timestamp;
        }
      }
    } catch (error) {
      console.warn(`Failed to analyze file ${file}:`, error);
    }
  }

  await updateProgress(job, { progress: 100, currentStep: 'Stats collection completed' });

  return {
    totalLines,
    totalFiles: logFiles.length,
    totalSize,
    levelDistribution,
    timeRange: startTime && endTime ? { start: startTime, end: endTime } : null
  };
}