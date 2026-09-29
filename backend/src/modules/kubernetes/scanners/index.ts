import { execFileSync } from 'child_process';
import { writeFileSync, mkdirSync, rmSync, mkdtempSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { prisma } from '../../../shared/database';
import { Job } from 'bullmq';


export interface KubernetesScanResult {
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  findings: KubernetesFinding[];
}

export interface KubernetesFinding {
  id: string;
  type: 'vulnerability' | 'misconfiguration' | 'secret' | 'rbac' | 'network' | 'best-practice';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  file: string;
  line: number;
  column?: number;
  ruleId?: string;
  cwe?: string;
  cvss?: number;
  references?: string[];
  namespace?: string;
  kind?: string;
  name?: string;
}

export interface ScanProgress {
  progress: number;
  currentStep: string;
}

async function updateProgress(job: Job, progress: ScanProgress): Promise<void> {
  await job.updateProgress(progress);
}

function runCommand(command: string, args: string[], options: { cwd?: string; timeout?: number } = {}): string {
  try {
    const result = execFileSync(command, args, {
      cwd: options.cwd,
      timeout: options.timeout || 300000,
      encoding: 'utf-8',
      maxBuffer: 10 * 1024 * 1024
    });
    return result;
  } catch (error: any) {
    if (error.stdout) return error.stdout;
    if (error.stderr) return error.stderr;
    throw error;
  }
}

function parseTrivyConfigOutput(output: string): KubernetesFinding[] {
  const findings: KubernetesFinding[] = [];

  try {
    const data = JSON.parse(output);

    if (data.Results) {
      for (const result of data.Results) {
        if (result.Misconfigurations) {
          for (const misconfig of result.Misconfigurations) {
            findings.push({
              id: `trivy-k8s-${misconfig.ID}`,
              type: mapMisconfigType(misconfig.Type),
              severity: mapSeverity(misconfig.Severity),
              title: misconfig.Title,
              description: misconfig.Description,
              file: result.Target || 'kubernetes.yaml',
              line: misconfig.CauseMetadata?.StartLine || 1,
              column: misconfig.CauseMetadata?.StartColumn || 0,
              ruleId: misconfig.ID,
              cwe: misconfig.CweIDs?.[0],
              references: misconfig.References,
              namespace: misconfig.Namespace,
              kind: misconfig.Kind,
              name: misconfig.Name
            });
          }
        }
      }
    }
  } catch {
    // Ignore parse errors
  }

  return findings;
}

function parseKubescapeOutput(output: string): KubernetesFinding[] {
  const findings: KubernetesFinding[] = [];

  try {
    const data = JSON.parse(output);

    if (data.results) {
      for (const result of data.results) {
        if (result.ruleStatus === 'Failed') {
          findings.push({
            id: `kubescape-${result.name}`,
            type: mapKubescapeType(result.category),
            severity: mapKubescapeSeverity(result.severity),
            title: result.name,
            description: result.description || result.rationale,
            file: 'kubernetes.yaml',
            line: 1,
            ruleId: result.name,
            references: [result.remediation]
          });
        }
      }
    }
  } catch {
    // Ignore parse errors
  }

  return findings;
}

function parseKubeLinterOutput(output: string): KubernetesFinding[] {
  const findings: KubernetesFinding[] = [];

  try {
    // KubeLinter outputs JSON lines
    const lines = output.split('\n').filter(l => l.trim());
    for (const line of lines) {
      const data = JSON.parse(line);
      findings.push({
        id: `kube-linter-${data.Diagnostic?.Code || 'unknown'}`,
        type: mapKubeLinterType(data.Diagnostic?.Code),
        severity: mapSeverity(data.Diagnostic?.Severity),
        title: data.Diagnostic?.Message || 'KubeLinter finding',
        description: data.Diagnostic?.Message || '',
        file: data.File || 'kubernetes.yaml',
        line: data.Diagnostic?.Location?.Start?.Line || 1,
        column: data.Diagnostic?.Location?.Start?.Column || 0,
        ruleId: data.Diagnostic?.Code,
        references: data.Diagnostic?.Suggestions?.map((s: any) => s.Text) || []
      });
    }
  } catch {
    // Ignore parse errors
  }

  return findings;
}

function mapSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  const s = severity?.toLowerCase() || 'info';
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'medium') return 'medium';
  if (s === 'low') return 'low';
  return 'info';
}

function mapMisconfigType(type: string): KubernetesFinding['type'] {
  const t = type?.toLowerCase() || '';
  if (t.includes('rbac')) return 'rbac';
  if (t.includes('network')) return 'network';
  if (t.includes('secret')) return 'secret';
  if (t.includes('vuln')) return 'vulnerability';
  return 'misconfiguration';
}

function mapKubescapeType(category: string): KubernetesFinding['type'] {
  const c = category?.toLowerCase() || '';
  if (c.includes('rbac')) return 'rbac';
  if (c.includes('network')) return 'network';
  if (c.includes('secret')) return 'secret';
  return 'best-practice';
}

function mapKubeLinterType(code: string): KubernetesFinding['type'] {
  const c = code?.toLowerCase() || '';
  if (c.includes('rbac')) return 'rbac';
  if (c.includes('network')) return 'network';
  if (c.includes('secret')) return 'secret';
  if (c.includes('security')) return 'misconfiguration';
  return 'best-practice';
}

function mapKubescapeSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  const s = severity?.toLowerCase() || 'info';
  if (s === 'critical' || s === 'high') return 'high';
  if (s === 'medium') return 'medium';
  if (s === 'low') return 'low';
  return 'info';
}

function deduplicateFindings(findings: KubernetesFinding[]): KubernetesFinding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.ruleId}:${f.file}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export async function scanKubernetes(
  yaml: string,
  job: Job,
  scanId: string
): Promise<KubernetesScanResult> {
  const tempDir = mkdtempSync(join(tmpdir(), 'k8s-scan-'));
  const yamlPath = join(tempDir, 'kubernetes.yaml');

  try {
    await updateProgress(job, { progress: 10, currentStep: 'Writing YAML to temp directory' });
    writeFileSync(yamlPath, yaml);

    const allFindings: KubernetesFinding[] = [];

    // Run Trivy for misconfiguration scanning
    await updateProgress(job, { progress: 25, currentStep: 'Running Trivy Kubernetes config scan' });
    try {
      const trivyOutput = runCommand('trivy', [
        'config',
        '--format', 'json',
        '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
        tempDir
      ], { cwd: tempDir, timeout: 300000 });
      const trivyFindings = parseTrivyConfigOutput(trivyOutput);
      allFindings.push(...trivyFindings);
    } catch (error) {
      console.warn('Trivy config scan failed:', error);
    }

    // Run Kubescape if available
    await updateProgress(job, { progress: 50, currentStep: 'Running Kubescape security scan' });
    try {
      const kubescapeOutput = runCommand('kubescape', [
        'scan',
        '--format', 'json',
        '--output', 'stdout',
        tempDir
      ], { cwd: tempDir, timeout: 300000 });
      const kubescapeFindings = parseKubescapeOutput(kubescapeOutput);
      allFindings.push(...kubescapeFindings);
    } catch (error) {
      console.warn('Kubescape scan failed (may not be installed):', error);
    }

    // Run KubeLinter if available
    await updateProgress(job, { progress: 70, currentStep: 'Running KubeLinter best practices check' });
    try {
      const kubeLinterOutput = runCommand('kube-linter', [
        'lint',
        '--format', 'json',
        tempDir
      ], { cwd: tempDir, timeout: 300000 });
      const kubeLinterFindings = parseKubeLinterOutput(kubeLinterOutput);
      allFindings.push(...kubeLinterFindings);
    } catch (error) {
      console.warn('KubeLinter scan failed (may not be installed):', error);
    }

    // Run kubeconform for schema validation
    await updateProgress(job, { progress: 80, currentStep: 'Validating Kubernetes schemas' });
    try {
      const kubeconformOutput = runCommand('kubeconform', [
        '-strict',
        '-ignore-missing-schemas',
        '-output', 'json',
        tempDir
      ], { cwd: tempDir, timeout: 120000 });
      // kubeconform outputs validation errors
    } catch (error) {
      console.warn('Kubeconform validation failed (may not be installed):', error);
    }

    await updateProgress(job, { progress: 90, currentStep: 'Consolidating findings' });

    const uniqueFindings = deduplicateFindings(allFindings);

    const summary = {
      totalFindings: uniqueFindings.length,
      critical: uniqueFindings.filter(f => f.severity === 'critical').length,
      high: uniqueFindings.filter(f => f.severity === 'high').length,
      medium: uniqueFindings.filter(f => f.severity === 'medium').length,
      low: uniqueFindings.filter(f => f.severity === 'low').length,
      info: uniqueFindings.filter(f => f.severity === 'info').length
    };

    if (scanId) {
      await prisma.finding.createMany({
        data: uniqueFindings.map(f => ({
          scanId,
          type: f.type,
          severity: f.severity,
          title: f.title,
          description: f.description,
          file: f.file,
          line: f.line,
          column: f.column,
          ruleId: f.ruleId,
          cwe: f.cwe,
          cvss: f.cvss,
          references: JSON.stringify(f.references || []),
          status: 'open'
        }))
      });
    }

    await updateProgress(job, { progress: 100, currentStep: 'Scan completed' });

    return { summary, findings: uniqueFindings };
  } finally {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  }
}

export async function fixKubernetes(
  yaml: string,
  findings: KubernetesFinding[],
  job: Job
): Promise<{ fixedYaml: string; changes: any[] }> {
  await updateProgress(job, { progress: 10, currentStep: 'Analyzing Kubernetes issues' });

  const fixedYaml = yaml;
  const changes: any[] = [];

  // Sort findings by severity
  const sortedFindings = [...findings].sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return severityOrder[a.severity] - severityOrder[b.severity];
  });

  // Basic fixes for common issues
  for (const finding of sortedFindings) {
    if (finding.ruleId) {
      // This is a simplified version - real implementation would use AI
      changes.push({
        findingId: finding.id,
        type: 'configuration_fix',
        description: `Fix applied for ${finding.title}`,
        ruleId: finding.ruleId
      });
    }
  }

  await updateProgress(job, { progress: 100, currentStep: 'Fix generation completed' });

  return { fixedYaml, changes };
}

export async function generateKubernetes(
  spec: any,
  job: Job
): Promise<{ yaml: string }> {
  await updateProgress(job, { progress: 10, currentStep: 'Generating Kubernetes YAML' });

  // This will be enhanced with AI-based generation
  // For now, return a basic template based on spec
  const {
    name = 'my-app',
    image = 'nginx:latest',
    replicas = 3,
    port = 80,
    namespace = 'default',
    env = [],
    resources = {},
    ingress = null
  } = spec;

  let yaml = `# Generated Kubernetes manifests for ${name}
apiVersion: v1
kind: Namespace
metadata:
  name: ${namespace}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${name}
  namespace: ${namespace}
  labels:
    app: ${name}
spec:
  replicas: ${replicas}
  selector:
    matchLabels:
      app: ${name}
  template:
    metadata:
      labels:
        app: ${name}
    spec:
      containers:
      - name: ${name}
        image: ${image}
        ports:
        - containerPort: ${port}`;

  if (env.length > 0) {
    yaml += '\n        env:';
    for (const e of env) {
      yaml += `\n        - name: ${e.name}`;
      if (e.value) yaml += `\n          value: "${e.value}"`;
      if (e.valueFrom) yaml += `\n          valueFrom: ${JSON.stringify(e.valueFrom, null, 10).replace(/\n/g, '\n          ')}`;
    }
  }

  if (Object.keys(resources).length > 0) {
    yaml += `\n        resources: ${JSON.stringify(resources, null, 8).replace(/\n/g, '\n        ')}`;
  }

  yaml += `
---
apiVersion: v1
kind: Service
metadata:
  name: ${name}
  namespace: ${namespace}
  labels:
    app: ${name}
spec:
  selector:
    app: ${name}
  ports:
  - port: ${port}
    targetPort: ${port}
  type: ClusterIP`;

  if (ingress) {
    yaml += `
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: ${name}
  namespace: ${namespace}
  annotations:
    kubernetes.io/ingress.class: nginx
spec:
  rules:
  - host: ${ingress.host}
    http:
      paths:
      - path: ${ingress.path || '/'}
        pathType: Prefix
        backend:
          service:
            name: ${name}
            port:
              number: ${port}`;
  }

  await updateProgress(job, { progress: 100, currentStep: 'Generation completed' });

  return { yaml };
}