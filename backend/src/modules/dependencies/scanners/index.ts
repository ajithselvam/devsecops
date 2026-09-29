import { execFileSync } from 'child_process';
import { writeFileSync, rmSync, mkdtempSync, mkdirSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { prisma } from '../../../shared/database';
import { Job } from 'bullmq';


export interface DependencyScanResult {
  summary: {
    totalDependencies: number;
    vulnerabilities: { critical: number; high: number; medium: number; low: number; info: number };
    outdated: number;
    licenses: Record<string, number>;
  };
  dependencies: DependencyInfo[];
  findings: DependencyFinding[];
  sbom?: any;
}

export interface DependencyInfo {
  name: string;
  version: string;
  type: string;
  location?: string;
  licenses?: string[];
  homepage?: string;
  repository?: string;
  description?: string;
  latestVersion?: string;
  outdated?: boolean;
  purl?: string;
  cpe?: string;
}

export interface DependencyFinding {
  id: string;
  type: 'vulnerability' | 'license' | 'outdated' | 'malicious';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  package: string;
  version: string;
  fixedVersion?: string;
  cve?: string;
  cwe?: string;
  cvss?: number;
  references?: string[];
  file?: string;
  line?: number;
}

export interface SBOMData {
  packages: SBOMPackage[];
  relationships: SBOMRelationship[];
  metadata: SBOMMetadata;
}

export interface SBOMPackage {
  name: string;
  version: string;
  type: string;
  licenses: string[];
  homepage?: string;
  repository?: string;
  description?: string;
  cpe?: string;
  purl?: string;
  hashes?: Record<string, string>;
}

export interface SBOMRelationship {
  refA: string;
  refB: string;
  type: string;
}

export interface SBOMMetadata {
  timestamp: string;
  tool: string;
  component?: {
    name: string;
    version: string;
  };
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
      maxBuffer: 50 * 1024 * 1024
    });
    return result;
  } catch (error: any) {
    if (error.stdout) return error.stdout;
    if (error.stderr) return error.stderr;
    throw error;
  }
}

function parseSyftOutput(output: string): DependencyInfo[] {
  const dependencies: DependencyInfo[] = [];

  try {
    const data = JSON.parse(output);

    if (data.artifacts) {
      for (const artifact of data.artifacts) {
        const licenses = artifact.licenses?.map((l: any) => l.value || l.name || l.spdx_id || l).filter(Boolean) || [];

        dependencies.push({
          name: artifact.name,
          version: artifact.version,
          type: artifact.type,
          location: artifact.locations?.[0]?.path,
          licenses,
          homepage: artifact.homepage,
          repository: artifact.repository,
          description: artifact.description,
          purl: artifact.purl,
          cpe: artifact.cpe
        });
      }
    }
  } catch {
    // Ignore parse errors
  }

  return dependencies;
}

function parseGrypeOutput(output: string): DependencyFinding[] {
  const findings: DependencyFinding[] = [];

  try {
    const data = JSON.parse(output);

    if (data.matches) {
      for (const match of data.matches) {
        const vuln = match.vulnerability;
        const artifact = match.artifact;

        findings.push({
          id: `grype-${vuln.id}-${artifact.name}`,
          type: 'vulnerability',
          severity: mapSeverity(vuln.severity),
          title: vuln.id,
          description: vuln.description || `${vuln.id} in ${artifact.name}@${artifact.version}`,
          package: artifact.name,
          version: artifact.version,
          fixedVersion: vuln.fix?.versions?.[0],
          cve: vuln.id.startsWith('CVE-') ? vuln.id : undefined,
          cwe: vuln.cwes?.[0],
          cvss: vuln.cvss?.[0]?.metrics?.baseScore,
          references: vuln.urls,
          file: artifact.locations?.[0]?.path
        });
      }
    }
  } catch {
    // Ignore parse errors
  }

  return findings;
}

function parseTrivyOutput(output: string): DependencyFinding[] {
  const findings: DependencyFinding[] = [];

  try {
    const data = JSON.parse(output);

    if (data.Results) {
      for (const result of data.Results) {
        if (result.Vulnerabilities) {
          for (const vuln of result.Vulnerabilities) {
            findings.push({
              id: `trivy-${vuln.VulnerabilityID}-${result.Target}`,
              type: 'vulnerability',
              severity: mapSeverity(vuln.Severity),
              title: vuln.VulnerabilityID,
              description: vuln.Description || `${vuln.VulnerabilityID} in ${vuln.PkgName}@${vuln.InstalledVersion}`,
              package: vuln.PkgName,
              version: vuln.InstalledVersion,
              fixedVersion: vuln.FixedVersion,
              cve: vuln.VulnerabilityID,
              cwe: vuln.CweIDs?.[0],
              cvss: vuln.CVSS?.nvd?.V3Score,
              references: vuln.References,
              file: result.Target
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

function parseSyftSbom(output: string): SBOMData {
  try {
    const data = JSON.parse(output);

    const packages: SBOMPackage[] = [];
    const relationships: SBOMRelationship[] = [];

    if (data.artifacts) {
      for (const artifact of data.artifacts) {
        const licenses = artifact.licenses?.map((l: any) => l.value || l.name || l.spdx_id || l).filter(Boolean) || [];

        packages.push({
          name: artifact.name,
          version: artifact.version,
          type: artifact.type,
          licenses,
          homepage: artifact.homepage,
          repository: artifact.repository,
          description: artifact.description,
          cpe: artifact.cpe,
          purl: artifact.purl,
          hashes: artifact.hashes
        });
      }
    }

    if (data.artifactRelationships) {
      for (const rel of data.artifactRelationships) {
        relationships.push({
          refA: rel.parent,
          refB: rel.child,
          type: rel.type
        });
      }
    }

    return {
      packages,
      relationships,
      metadata: {
        timestamp: new Date().toISOString(),
        tool: 'Syft',
        component: data.source?.target ? { name: data.source.target, version: '1.0.0' } : undefined
      }
    };
  } catch {
    return { packages: [], relationships: [], metadata: { timestamp: new Date().toISOString(), tool: 'Syft' } };
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

function deduplicateFindings(findings: DependencyFinding[]): DependencyFinding[] {
  const seen = new Set<string>();
  return findings.filter(f => {
    const key = `${f.cve || f.title}:${f.package}:${f.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function checkOutdated(dependencies: DependencyInfo[]): DependencyInfo[] {
  // This would ideally check against registries (npm, PyPI, Maven, etc.)
  // For now, we'll mark as outdated if we can't determine
  return dependencies.map(dep => ({
    ...dep,
    outdated: false, // Would need registry checks
    latestVersion: dep.version
  }));
}

function persistDependencyFindings(scanId: string, findings: DependencyFinding[]) {
  if (!scanId || findings.length === 0) return Promise.resolve();
  return prisma.finding.createMany({
    data: findings.map(f => ({
      scanId,
      type: f.type === 'vulnerability' ? 'vulnerability' : 'security_issue',
      severity: f.severity,
      title: (f.title || f.cve || f.package).slice(0, 500),
      description: f.description,
      file: f.file || 'dependencies',
      line: f.line || 0,
      ruleId: f.cve || f.id,
      cwe: typeof f.cwe === 'string' ? f.cwe : undefined,
      cvssScore: typeof f.cvss === 'number' ? f.cvss : undefined,
      cve: f.cve,
      package: f.package,
      installedVersion: f.version,
      fixedVersion: f.fixedVersion,
      references: JSON.stringify(f.references || []),
      status: 'open'
    }))
  });
}

export async function scanDependencies(
  input: { repoUrl?: string; branch?: string; manifest?: string; format?: string; filename?: string },
  job: Job,
  scanId: string
): Promise<DependencyScanResult> {
  const tempDir = mkdtempSync(join(tmpdir(), 'dep-scan-'));
  const workDir = join(tempDir, 'src');

  try {
    await updateProgress(job, { progress: 5, currentStep: 'Preparing scan environment' });

    if (input.repoUrl) {
      await updateProgress(job, { progress: 10, currentStep: 'Cloning repository' });
      const repoUrl = input.repoUrl.replace(/\.git$/i, '');
      try {
        runCommand('git', ['clone', '--depth', '1', '--branch', input.branch || 'main', `${repoUrl}.git`, workDir], { timeout: 180000 });
      } catch {
        runCommand('git', ['clone', '--depth', '1', `${repoUrl}.git`, workDir], { timeout: 180000 });
      }
    } else if (input.manifest) {
      await updateProgress(job, { progress: 10, currentStep: 'Writing manifest file' });
      mkdirSync(workDir, { recursive: true });
      writeFileSync(join(workDir, filenameForFormat(input.format, input.filename)), input.manifest);
    } else {
      mkdirSync(workDir, { recursive: true });
    }

    await updateProgress(job, { progress: 20, currentStep: 'Running Syft for SBOM generation' });
    let dependencies: DependencyInfo[] = [];
    let sbom: SBOMData = { packages: [], relationships: [], metadata: { timestamp: new Date().toISOString(), tool: 'Syft' } };

    try {
      const syftOutput = runCommand('syft', [
        'dir:' + workDir,
        '-o', 'json'
      ], { cwd: workDir, timeout: 180000 });
      dependencies = parseSyftOutput(syftOutput);
      sbom = parseSyftSbom(syftOutput);
    } catch (error) {
      console.warn('Syft scan failed:', error);
    }

    if (dependencies.length === 0 && input.manifest) {
      dependencies = parseManifestText(input.manifest, input.format, input.filename);
    }

    await updateProgress(job, { progress: 45, currentStep: 'Running Grype vulnerability scan' });
    let grypeFindings: DependencyFinding[] = [];
    try {
      const grypeOutput = runCommand('grype', [
        'dir:' + workDir,
        '-o', 'json',
        '--add-cpes-if-none'
      ], { cwd: workDir, timeout: 180000 });
      grypeFindings = parseGrypeOutput(grypeOutput);
    } catch (error) {
      console.warn('Grype scan failed:', error);
    }

    await updateProgress(job, { progress: 65, currentStep: 'Running Trivy vulnerability scan' });
    let trivyFindings: DependencyFinding[] = [];
    try {
      const trivyOutput = runCommand('trivy', [
        'fs',
        '--format', 'json',
        '--scanners', 'vuln',
        '--severity', 'CRITICAL,HIGH,MEDIUM,LOW',
        workDir
      ], { cwd: workDir, timeout: 180000 });
      trivyFindings = parseTrivyOutput(trivyOutput);
    } catch (error) {
      console.warn('Trivy scan failed:', error);
    }

    await updateProgress(job, { progress: 80, currentStep: 'Checking for outdated dependencies' });
    dependencies = checkOutdated(dependencies);

    await updateProgress(job, { progress: 90, currentStep: 'Consolidating results' });

    const allFindings = deduplicateFindings([...grypeFindings, ...trivyFindings]);

    for (const dep of dependencies) {
      if (dep.outdated && dep.latestVersion && dep.latestVersion !== dep.version) {
        allFindings.push({
          id: `outdated-${dep.name}`,
          type: 'outdated',
          severity: 'low',
          title: `Outdated dependency: ${dep.name}`,
          description: `${dep.name}@${dep.version} is outdated. Latest: ${dep.latestVersion}`,
          package: dep.name,
          version: dep.version,
          fixedVersion: dep.latestVersion
        });
      }
    }

    const licenses: Record<string, number> = {};
    for (const dep of dependencies) {
      for (const license of dep.licenses || []) {
        licenses[license] = (licenses[license] || 0) + 1;
      }
    }

    const summary = {
      totalDependencies: dependencies.length,
      vulnerabilities: {
        critical: allFindings.filter(f => f.severity === 'critical' && f.type === 'vulnerability').length,
        high: allFindings.filter(f => f.severity === 'high' && f.type === 'vulnerability').length,
        medium: allFindings.filter(f => f.severity === 'medium' && f.type === 'vulnerability').length,
        low: allFindings.filter(f => f.severity === 'low' && f.type === 'vulnerability').length,
        info: allFindings.filter(f => f.severity === 'info' && f.type === 'vulnerability').length
      },
      outdated: allFindings.filter(f => f.type === 'outdated').length,
      licenses
    };

    if (scanId) {
      await persistDependencyFindings(scanId, allFindings);
    }

    await updateProgress(job, { progress: 100, currentStep: 'Scan completed' });

    return {
      summary,
      dependencies,
      findings: allFindings,
      sbom
    };
  } finally {
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  }
}

function filenameForFormat(format?: string, originalName?: string): string {
  if (originalName) return originalName;
  switch (format) {
    case 'package-json': return 'package.json';
    case 'pom-xml': return 'pom.xml';
    case 'requirements-txt': return 'requirements.txt';
    case 'go-mod': return 'go.mod';
    case 'cargo-toml': return 'Cargo.toml';
    case 'composer-json': return 'composer.json';
    case 'gemfile': return 'Gemfile';
    default: return 'package.json';
  }
}

function parseManifestText(manifest: string, format?: string, filename?: string): DependencyInfo[] {
  const name = (filename || '').toLowerCase();
  const kind = format || (name.includes('requirements') ? 'requirements-txt' : name.includes('pom') ? 'pom-xml' : name.includes('go.mod') ? 'go-mod' : 'package-json');
  const deps: DependencyInfo[] = [];

  try {
    if (kind === 'package-json' || name.endsWith('.json')) {
      const pkg = JSON.parse(manifest);
      const add = (obj: Record<string, string> | undefined, type: string) => {
        for (const [n, version] of Object.entries(obj || {})) {
          deps.push({
            name: n,
            version: String(version).replace(/^[^\d]*/, '') || String(version),
            type,
            outdated: false,
            latestVersion: String(version).replace(/^[^\d]*/, '') || String(version)
          });
        }
      };
      add(pkg.dependencies, 'npm');
      add(pkg.devDependencies, 'npm');
      add(pkg.optionalDependencies, 'npm');
    } else if (kind === 'requirements-txt') {
      for (const line of manifest.split('\n')) {
        const m = line.trim().match(/^([A-Za-z0-9_.-]+)\s*(?:==|>=|~=)?\s*([^\s;#]+)?/);
        if (m && m[1] && !m[1].startsWith('#')) {
          deps.push({ name: m[1], version: m[2] || 'latest', type: 'pypi' });
        }
      }
    } else if (kind === 'go-mod') {
      const matches = manifest.matchAll(/^\s*([^\s]+)\s+v[0-9][^\s]+/gm);
      for (const m of matches) {
        const parts = m[0].trim().split(/\s+/);
        deps.push({ name: parts[0], version: parts[1], type: 'go-module' });
      }
    }
  } catch {
    // ignore
  }
  return deps;
}

export async function remediateDependency(
  scanId: string,
  packageName: string,
  currentVersion: string,
  job: Job
): Promise<{ updatedManifest: string; changes: any[] }> {
  await updateProgress(job, { progress: 10, currentStep: 'Analyzing dependency for remediation' });

  // This will be enhanced with AI-based fixes
  // For now, return basic structure
  await updateProgress(job, { progress: 100, currentStep: 'Remediation analysis completed' });

  return {
    updatedManifest: '',
    changes: [{
      package: packageName,
      from: currentVersion,
      to: 'latest',
      type: 'version_update'
    }]
  };
}

export async function generateSBOM(
  scanId: string,
  format: 'cyclonedx' | 'spdx',
  job: Job
): Promise<{ sbom: SBOMData }> {
  await updateProgress(job, { progress: 10, currentStep: 'Generating SBOM' });

  const scan = await prisma.scan.findUnique({ where: { id: scanId } });
  if (!scan) {
    throw new Error('Scan not found');
  }

  // Retrieve the SBOM from scan metadata or regenerate
  const targetMeta = scan.targetMeta as any;
  let sbomData = targetMeta?.sbom;

  if (!sbomData) {
    // Regenerate if not stored
    if (scan.targetType === 'git_repo') {
      const tempDir = mkdtempSync(join(tmpdir(), 'sbom-'));
      try {
        runCommand('git', ['clone', '--depth', '1', '--branch', targetMeta?.branch || 'main', scan.targetValue, tempDir], { timeout: 300000 });
        const syftOutput = runCommand('syft', ['dir:' + tempDir, '-o', 'json'], { cwd: tempDir, timeout: 300000 });
        sbomData = parseSyftSbom(syftOutput);
      } finally {
        rmSync(tempDir, { recursive: true, force: true });
      }
    }
  }

  // Convert to requested format
  let output: string;
  if (format === 'cyclonedx') {
    output = convertToCycloneDX(sbomData!);
  } else {
    output = convertToSPDX(sbomData!);
  }

  await updateProgress(job, { progress: 100, currentStep: 'SBOM generation completed' });

  return { sbom: sbomData! };
}

function convertToCycloneDX(sbom: SBOMData): string {
  // Basic CycloneDX JSON format
  const components = sbom.packages.map(pkg => ({
    type: 'library',
    name: pkg.name,
    version: pkg.version,
    licenses: pkg.licenses.map(l => ({ license: { name: l } })),
    purl: pkg.purl,
    description: pkg.description,
    hashes: pkg.hashes ? Object.entries(pkg.hashes).map(([alg, val]) => ({ alg, content: val })) : [],
    externalReferences: pkg.repository ? [{ type: 'website', url: pkg.repository }] : []
  }));

  return JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: sbom.metadata.timestamp,
      tools: [{ name: sbom.metadata.tool }],
      component: sbom.metadata.component
    },
    components,
    dependencies: sbom.relationships.map(rel => ({
      ref: rel.refA,
      dependsOn: [rel.refB]
    }))
  }, null, 2);
}

function convertToSPDX(sbom: SBOMData): string {
  // Basic SPDX tag-value format
  let output = `SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: ${sbom.metadata.component?.name || 'SBOM'}
DocumentNamespace: https://devsecops.ai/sbom/${crypto.randomUUID()}
Creator: Tool: ${sbom.metadata.tool}
Created: ${sbom.metadata.timestamp}
`;

  for (const pkg of sbom.packages) {
    const spdxId = `SPDXRef-${pkg.name.replace(/[^a-zA-Z0-9.-]/g, '-')}-${pkg.version}`;
    output += `
PackageName: ${pkg.name}
SPDXID: ${spdxId}
PackageVersion: ${pkg.version}
PackageDownloadLocation: ${pkg.repository || 'NOASSERTION'}
FilesAnalyzed: false
LicenseConcluded: ${pkg.licenses.join(' OR ') || 'NOASSERTION'}
LicenseDeclared: ${pkg.licenses.join(' OR ') || 'NOASSERTION'}
CopyrightText: NOASSERTION
`;
    if (pkg.description) {
      output += `PackageDescription: ${pkg.description}\n`;
    }
    if (pkg.homepage) {
      output += `PackageHomePage: ${pkg.homepage}\n`;
    }
  }

  return output;
}

// Need crypto for UUID
import crypto from 'crypto';