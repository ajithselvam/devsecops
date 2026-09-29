import { execFileSync } from 'child_process';
import { writeFileSync, mkdirSync, rmSync, mkdtempSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { prisma } from '../../../shared/database';
import { Job } from 'bullmq';


export interface DockerfileScanResult {
  summary: {
    totalFindings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  findings: DockerfileFinding[];
  sbom?: any;
}

export interface DockerfileFinding {
  id: string;
  type: string;
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
  fixable?: boolean;
  fixedVersion?: string;
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

function parseGrypeOutput(output: string): DockerfileFinding[] {
  const findings: DockerfileFinding[] = [];

  try {
    // Grype JSON output
    const data = JSON.parse(output);

    if (data.matches) {
      for (const match of data.matches) {
        const vuln = match.vulnerability;
        const artifact = match.artifact;

        findings.push({
          id: `grype-${vuln.id}`,
          type: 'vulnerability',
          severity: mapSeverity(vuln.severity),
          title: vuln.id,
          description: vuln.description || `${vuln.id} in ${artifact.name}@${artifact.version}`,
          file: 'Dockerfile',
          line: 1,
          column: 0,
          ruleId: vuln.id,
          cwe: vuln.cwes?.[0],
          cvss: vuln.cvss?.[0]?.metrics?.baseScore,
          references: vuln.urls,
          fixable: !!vuln.fix?.versions?.length,
          fixedVersion: vuln.fix?.versions?.[0]
        });
      }
    }
  } catch {
    // Try table format parsing
    const lines = output.split('\n');
    for (const line of lines) {
      if (line.includes('CVE-') || line.includes('GHSA-')) {
        const parts = line.split(/\s+/);
        if (parts.length >= 3) {
          findings.push({
            id: `grype-${parts[0]}`,
            type: 'vulnerability',
            severity: mapSeverity(parts[2]),
            title: parts[0],
            description: line,
            file: 'Dockerfile',
            line: 1,
            ruleId: parts[0]
          });
        }
      }
    }
  }

  return findings;
}

function parseTrivyOutput(output: string): DockerfileFinding[] {
  const findings: DockerfileFinding[] = [];

  try {
    const data = JSON.parse(output);

    if (data.Results) {
      for (const result of data.Results) {
        if (result.Vulnerabilities) {
          for (const vuln of result.Vulnerabilities) {
            findings.push({
              id: `trivy-${vuln.VulnerabilityID}`,
              type: 'vulnerability',
              severity: mapSeverity(vuln.Severity),
              title: vuln.VulnerabilityID,
              description: vuln.Description || `${vuln.VulnerabilityID} in ${vuln.PkgName}@${vuln.InstalledVersion}`,
              file: 'Dockerfile',
              line: 1,
              column: 0,
              ruleId: vuln.VulnerabilityID,
              cwe: vuln.CweIDs?.[0],
              cvss: vuln.CVSS?.nvd?.V3Score,
              references: vuln.References,
              fixable: !!vuln.FixedVersion,
              fixedVersion: vuln.FixedVersion
            });
          }
        }

        // Misconfigurations
        if (result.Misconfigurations) {
          for (const misconfig of result.Misconfigurations) {
            findings.push({
              id: `trivy-misconfig-${misconfig.ID}`,
              type: 'misconfiguration',
              severity: mapSeverity(misconfig.Severity),
              title: misconfig.Title,
              description: misconfig.Description,
              file: 'Dockerfile',
              line: misconfig.CauseMetadata?.StartLine || 1,
              column: misconfig.CauseMetadata?.StartColumn || 0,
              ruleId: misconfig.ID,
              cwe: misconfig.CweIDs?.[0],
              references: misconfig.References
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

function parseSyftOutput(output: string): any {
  try {
    return JSON.parse(output);
  } catch {
    return null;
  }
}

function mapSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  const s = severity?.toLowerCase() || 'info';
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'medium') return 'medium';
  if (s === 'low') return 'low';
  return 'info';
}

function deduplicateFindings(findings: DockerfileFinding[]): DockerfileFinding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.ruleId}:${f.file}:${f.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export async function scanDockerfile(
  dockerfile: string,
  job: Job,
  scanId: string
): Promise<DockerfileScanResult> {
  const tempDir = mkdtempSync(join(tmpdir(), 'dockerfile-scan-'));
  const dockerfilePath = join(tempDir, 'Dockerfile');

  try {
    await updateProgress(job, { progress: 15, currentStep: 'Writing Dockerfile to temp directory' });
    writeFileSync(dockerfilePath, dockerfile);

    await updateProgress(job, { progress: 20, currentStep: 'Running Syft for SBOM generation' });
    let sbom: any = null;
    try {
      const syftOutput = runCommand('syft', [
        'dir:' + tempDir,
        '-o', 'json',
        '--scope', 'all-layers'
      ], { cwd: tempDir });
      sbom = parseSyftOutput(syftOutput);
    } catch (error) {
      console.warn('Syft scan failed:', error);
    }

    await updateProgress(job, { progress: 40, currentStep: 'Running Grype vulnerability scan' });
    let grypeFindings: DockerfileFinding[] = [];
    try {
      const grypeOutput = runCommand('grype', [
        'dir:' + tempDir,
        '-o', 'json',
        '--scope', 'all-layers',
        '--add-cpes-if-none'
      ], { cwd: tempDir, timeout: 300000 });
      grypeFindings = parseGrypeOutput(grypeOutput);
    } catch (error) {
      console.warn('Grype scan failed:', error);
    }

    await updateProgress(job, { progress: 65, currentStep: 'Running Trivy vulnerability scan' });
    let trivyFindings: DockerfileFinding[] = [];
    try {
      const trivyOutput = runCommand('trivy', [
        'fs',
        '--format', 'json',
        '--scanners', 'vuln,config',
        '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
        tempDir
      ], { cwd: tempDir, timeout: 300000 });
      trivyFindings = parseTrivyOutput(trivyOutput);
    } catch (error) {
      console.warn('Trivy scan failed:', error);
    }

    await updateProgress(job, { progress: 85, currentStep: 'Consolidating findings' });

    // Combine findings from all scanners
    const allFindings = deduplicateFindings([...grypeFindings, ...trivyFindings]);

    const summary = {
      totalFindings: allFindings.length,
      critical: allFindings.filter(f => f.severity === 'critical').length,
      high: allFindings.filter(f => f.severity === 'high').length,
      medium: allFindings.filter(f => f.severity === 'medium').length,
      low: allFindings.filter(f => f.severity === 'low').length,
      info: allFindings.filter(f => f.severity === 'info').length
    };

    // Save findings to database
    if (scanId) {
      await prisma.finding.createMany({
        data: allFindings.map(f => ({
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
          references: JSON.stringify(f.references || []),
          fixable: f.fixable,
          fixedVersion: f.fixedVersion,
          status: 'open'
        }))
      });
    }

    await updateProgress(job, { progress: 100, currentStep: 'Scan completed' });

    return {
      summary,
      findings: allFindings,
      sbom
    };
  } finally {
    // Cleanup
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  }
}

export async function fixDockerfile(
  dockerfile: string,
  findings: DockerfileFinding[],
  job: Job
): Promise<{ fixedDockerfile: string; changes: any[] }> {
  await updateProgress(job, { progress: 10, currentStep: 'Analyzing Dockerfile issues' });

  // This will be enhanced with AI-based fixes
  // For now, return the original with basic fixes
  let fixedDockerfile = dockerfile;
  const changes: any[] = [];

  // Sort findings by severity
  const sortedFindings = [...findings].sort((a, b) => {
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    return severityOrder[a.severity] - severityOrder[b.severity];
  });

  for (const finding of sortedFindings) {
    if (finding.fixable && finding.fixedVersion) {
      // Apply version updates where possible
      // This is a simplified version - real implementation would use AI
      const regex = new RegExp(`(${finding.title.split(' ')[0]}\\s+)([^\\s]+)`, 'g');
      const match = fixedDockerfile.match(regex);
      if (match) {
        const oldVersion = match[0].split(/\s+/)[1];
        fixedDockerfile = fixedDockerfile.replace(oldVersion, finding.fixedVersion);
        changes.push({
          findingId: finding.id,
          type: 'version_update',
          description: `Updated ${finding.title} from ${oldVersion} to ${finding.fixedVersion}`,
          before: oldVersion,
          after: finding.fixedVersion
        });
      }
    }
  }

  await updateProgress(job, { progress: 100, currentStep: 'Fix generation completed' });

  return { fixedDockerfile, changes };
}

export async function scanDockerImage(
  imageName: string,
  job: Job,
  scanId: string
): Promise<DockerfileScanResult> {
  await updateProgress(job, { progress: 10, currentStep: 'Pulling image metadata' });

  // Optional: check if image exists locally if Docker daemon is running
  try {
    runCommand('docker', ['inspect', imageName], { timeout: 10000 });
  } catch {
    // If local docker daemon is down or image is not local, Grype / Syft / Trivy will fetch it from registry
  }

  await updateProgress(job, { progress: 30, currentStep: 'Running Syft for SBOM generation' });
  let sbom: any = null;
  try {
    const syftOutput = runCommand('syft', [
      imageName,
      '-o', 'json',
      '--scope', 'all-layers'
    ], { timeout: 300000 });
    sbom = parseSyftOutput(syftOutput);
  } catch (error) {
    console.warn('Syft scan failed:', error);
  }

  await updateProgress(job, { progress: 50, currentStep: 'Running Grype vulnerability scan' });
  let grypeFindings: DockerfileFinding[] = [];
  try {
    const grypeOutput = runCommand('grype', [
      imageName,
      '-o', 'json',
      '--scope', 'all-layers',
      '--add-cpes-if-none'
    ], { timeout: 300000 });
    grypeFindings = parseGrypeOutput(grypeOutput);
  } catch (error) {
    console.warn('Grype scan failed:', error);
  }

  await updateProgress(job, { progress: 70, currentStep: 'Running Trivy vulnerability scan' });
  let trivyFindings: DockerfileFinding[] = [];
  try {
    const trivyOutput = runCommand('trivy', [
      'image',
      '--format', 'json',
      '--scanners', 'vuln,config',
      '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
      imageName
    ], { timeout: 300000 });
    trivyFindings = parseTrivyOutput(trivyOutput);
  } catch (error) {
    console.warn('Trivy scan failed:', error);
  }

  await updateProgress(job, { progress: 85, currentStep: 'Consolidating findings' });

  const allFindings = deduplicateFindings([...grypeFindings, ...trivyFindings]);

  const summary = {
    totalFindings: allFindings.length,
    critical: allFindings.filter(f => f.severity === 'critical').length,
    high: allFindings.filter(f => f.severity === 'high').length,
    medium: allFindings.filter(f => f.severity === 'medium').length,
    low: allFindings.filter(f => f.severity === 'low').length,
    info: allFindings.filter(f => f.severity === 'info').length
  };

  if (scanId) {
    await prisma.finding.createMany({
      data: allFindings.map(f => ({
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
        references: JSON.stringify(f.references || []),
        fixable: f.fixable,
        fixedVersion: f.fixedVersion,
        status: 'open'
      }))
    });
  }

  await updateProgress(job, { progress: 100, currentStep: 'Scan completed' });

  return {
    summary,
    findings: allFindings,
    sbom
  };
}

export async function fixDockerImage(
  dockerfile: string,
  vulnerabilities: DockerfileFinding[],
  job: Job
): Promise<{ fixedDockerfile: string; beforeVulnerabilities: DockerfileFinding[]; afterVulnerabilities: DockerfileFinding[] }> {
  await updateProgress(job, { progress: 10, currentStep: 'Analyzing vulnerabilities for base image fixes' });

  // This will be enhanced with AI to suggest base image upgrades
  // For now, return basic structure
  const changes: any[] = [];

  await updateProgress(job, { progress: 100, currentStep: 'Fix analysis completed' });

  return {
    fixedDockerfile: dockerfile,
    beforeVulnerabilities: vulnerabilities,
    afterVulnerabilities: vulnerabilities
  };
}