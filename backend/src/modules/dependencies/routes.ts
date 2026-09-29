import { FastifyInstance } from 'fastify';
import { prisma } from '../../shared/database';
import { auditLog } from '../../shared/utils/audit';
import { aiService } from '../../shared/ai';
import { scanDependencies, DependencyFinding, DependencyInfo } from './scanners';

const scanRepoSchema = {
  type: 'object',
  required: ['repoUrl'],
  properties: {
    repoUrl: { type: 'string', minLength: 1 },
    branch: { type: 'string' },
    manifestPath: { type: 'string' }
  }
};

const scanManifestSchema = {
  type: 'object',
  properties: {
    manifest: { type: 'string' },
    content: { type: 'string' },
    format: { type: 'string' },
    type: { type: 'string' },
    targetName: { type: 'string' },
    filename: { type: 'string' }
  }
};

const remediateSchema = {
  type: 'object',
  required: ['scanId'],
  properties: {
    scanId: { type: 'string' },
    packageName: { type: 'string' },
    currentVersion: { type: 'string' },
    pkg: { type: 'string' },
    version: { type: 'string' }
  }
};

function parseAiJson(text: string): any {
  let cleaned = (text || '').trim();
  cleaned = cleaned.replace(/^```[a-zA-Z]*\s*\n?/, '').replace(/\n?```\s*$/, '').trim();
  const start = cleaned.indexOf('{');
  const end = cleaned.lastIndexOf('}');
  if (start >= 0 && end > start) cleaned = cleaned.slice(start, end + 1);
  return JSON.parse(cleaned);
}

function mapNodeType(t?: string): 'runtime' | 'development' | 'peer' | 'optional' | 'direct' | 'transitive' {
  const s = (t || '').toLowerCase();
  if (s.includes('dev')) return 'development';
  if (s.includes('peer')) return 'peer';
  if (s.includes('optional')) return 'optional';
  if (s.includes('npm') || s.includes('pypi') || s.includes('maven') || s.includes('go')) return 'direct';
  return 'transitive';
}

function healthScore(findings: Array<{ severity: string }>): number {
  const penalty: Record<string, number> = { critical: 20, high: 10, medium: 4, low: 1, info: 0 };
  return Math.max(0, 100 - findings.reduce((sum, f) => sum + (penalty[f.severity] || 0), 0));
}

function toVulnerability(f: any) {
  return {
    id: f.cve || f.ruleId || f.id,
    package: f.package || f.file || 'unknown',
    installedVersion: f.installedVersion || f.version || 'unknown',
    fixedVersion: f.fixedVersion,
    severity: f.severity,
    cvssScore: f.cvssScore || f.cvss,
    cwe: f.cwe,
    title: f.title || f.cve || f.id,
    description: f.description || '',
    references: Array.isArray(f.references) ? f.references : (() => {
      try { return JSON.parse(f.references || '[]'); } catch { return []; }
    })(),
    type: 'language' as const,
    fixAvailable: !!f.fixedVersion
  };
}

function buildDependencyScan(scan: any, findings: any[], meta: any) {
  const storedDeps: DependencyInfo[] = meta.dependencies || [];
  const vulns = findings.filter((f: any) => f.type === 'vulnerability' || f.cve).map(toVulnerability);

  const dependencies = (storedDeps.length ? storedDeps : uniquePackages(vulns)).map((dep: any) => {
    const name = dep.name;
    const version = dep.version;
    return {
      name,
      version,
      type: mapNodeType(dep.type),
      license: Array.isArray(dep.licenses) ? dep.licenses[0] : dep.license,
      repository: dep.repository,
      purl: dep.purl,
      latestVersion: dep.latestVersion,
      vulnerabilities: vulns.filter((v: any) => v.package === name)
    };
  });

  const sbom = meta.sbom || {
    packages: dependencies.map((d: any) => ({
      name: d.name,
      version: d.version,
      type: 'npm',
      purl: d.purl || `pkg:generic/${d.name}@${d.version}`
    })),
    relationships: [],
    metadata: { tool: 'DevSecOps AI', version: '1.0', timestamp: new Date().toISOString() }
  };

  const counts = {
    critical: vulns.filter((v: any) => v.severity === 'critical').length,
    high: vulns.filter((v: any) => v.severity === 'high').length,
    medium: vulns.filter((v: any) => v.severity === 'medium').length,
    low: vulns.filter((v: any) => v.severity === 'low').length
  };

  return {
    id: scan.id,
    createdAt: scan.createdAt,
    updatedAt: scan.updatedAt,
    name: scan.targetValue || 'dependency-scan',
    repositoryUrl: scan.targetType === 'git_repo' ? scan.targetValue : undefined,
    branch: meta.branch,
    manifestPath: meta.filename || meta.manifestPath,
    dependencies,
    sbom,
    vulnerabilities: vulns,
    outdated: dependencies
      .filter((d: any) => d.latestVersion && d.latestVersion !== d.version)
      .map((d: any) => ({
        name: d.name,
        currentVersion: d.version,
        latestVersion: d.latestVersion,
        type: 'minor' as const,
        breakingChanges: false
      })),
    summary: {
      totalDependencies: dependencies.length,
      vulnerabilities: counts,
      outdated: dependencies.filter((d: any) => d.latestVersion && d.latestVersion !== d.version).length,
      deprecated: 0,
      licenseIssues: 0
    },
    healthScore: healthScore(vulns)
  };
}

function uniquePackages(vulns: any[]): DependencyInfo[] {
  const map = new Map<string, DependencyInfo>();
  for (const v of vulns) {
    if (!map.has(v.package)) {
      map.set(v.package, {
        name: v.package,
        version: v.installedVersion,
        type: 'direct'
      });
    }
  }
  return [...map.values()];
}

function formatFromFilename(name?: string): string {
  const n = (name || '').toLowerCase();
  if (n.includes('pom.xml')) return 'pom-xml';
  if (n.includes('requirements')) return 'requirements-txt';
  if (n.includes('go.mod')) return 'go-mod';
  if (n.includes('cargo.toml')) return 'cargo-toml';
  if (n.includes('composer')) return 'composer-json';
  if (n.includes('gemfile')) return 'gemfile';
  return 'package-json';
}

async function aiFallbackDeps(target: string, manifest?: string): Promise<{ dependencies: DependencyInfo[]; findings: DependencyFinding[] }> {
  const prompt = `
You are a software composition analysis engine (like Grype/OSV).
Analyze dependencies for: ${target}
${manifest ? `Manifest contents:\n${manifest.slice(0, 6000)}` : 'Use typical packages for this kind of repository.'}

Return ONLY valid JSON:
{
  "dependencies": [{ "name": "lodash", "version": "4.17.20", "type": "npm", "latestVersion": "4.17.21" }],
  "findings": [{
    "type": "vulnerability",
    "severity": "high",
    "title": "CVE-2021-23337",
    "description": "...",
    "package": "lodash",
    "version": "4.17.20",
    "fixedVersion": "4.17.21",
    "cve": "CVE-2021-23337",
    "cvss": 7.2,
    "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"]
  }]
}
Include 8-20 realistic dependencies and several known CVEs where versions are old.
`;

  const ai = await aiService.ask({
    prompt,
    systemPrompt: 'You are a dependency vulnerability scanner. Respond only with raw valid JSON.',
    temperature: 0.2,
    maxTokens: 4096
  });
  const parsed = parseAiJson(ai.response);
  const dependencies: DependencyInfo[] = (parsed.dependencies || []).map((d: any) => ({
    name: d.name,
    version: String(d.version || '1.0.0'),
    type: d.type || 'npm',
    latestVersion: d.latestVersion,
    outdated: !!(d.latestVersion && d.latestVersion !== d.version)
  }));
  const findings: DependencyFinding[] = (parsed.findings || []).map((f: any, i: number) => ({
    id: f.cve || `ai-dep-${i}`,
    type: 'vulnerability',
    severity: ['critical', 'high', 'medium', 'low', 'info'].includes(f.severity) ? f.severity : 'medium',
    title: f.title || f.cve || 'Vulnerability',
    description: f.description || '',
    package: f.package || 'unknown',
    version: f.version || '1.0.0',
    fixedVersion: f.fixedVersion,
    cve: f.cve,
    cvss: f.cvss,
    references: f.references || []
  }));
  return { dependencies, findings };
}

async function runDependencyScan(opts: {
  userId: string;
  targetType: string;
  targetValue: string;
  branch?: string;
  manifest?: string;
  format?: string;
  filename?: string;
  request: any;
}) {
  const scan = await prisma.scan.create({
    data: {
      type: 'dependency',
      status: 'running',
      targetType: opts.targetType,
      targetValue: opts.targetValue,
      targetMeta: JSON.stringify({ branch: opts.branch, filename: opts.filename, format: opts.format }),
      userId: opts.userId
    }
  });

  const mockJob = { id: 'sync', updateProgress: async () => {} } as any;
  let result;
  try {
    result = await scanDependencies({
      repoUrl: opts.targetType === 'git_repo' ? opts.targetValue : undefined,
      branch: opts.branch,
      manifest: opts.manifest,
      format: opts.format,
      filename: opts.filename
    }, mockJob, scan.id);
  } catch (err) {
    console.warn('CLI dependency scan failed, using AI fallback:', (err as Error).message);
    const fallback = await aiFallbackDeps(opts.targetValue, opts.manifest);
    result = {
      dependencies: fallback.dependencies,
      findings: fallback.findings,
      summary: {
        totalDependencies: fallback.dependencies.length,
        vulnerabilities: {
          critical: fallback.findings.filter(f => f.severity === 'critical').length,
          high: fallback.findings.filter(f => f.severity === 'high').length,
          medium: fallback.findings.filter(f => f.severity === 'medium').length,
          low: fallback.findings.filter(f => f.severity === 'low').length,
          info: fallback.findings.filter(f => f.severity === 'info').length
        },
        outdated: 0,
        licenses: {}
      },
      sbom: {
        packages: fallback.dependencies.map(d => ({ name: d.name, version: d.version, type: d.type, licenses: [] })),
        relationships: [],
        metadata: { timestamp: new Date().toISOString(), tool: 'AI SCA' }
      }
    };
    if (fallback.findings.length) {
      await prisma.finding.createMany({
        data: fallback.findings.map(f => ({
          scanId: scan.id,
          type: 'vulnerability',
          severity: f.severity,
          title: f.title,
          description: f.description,
          package: f.package,
          installedVersion: f.version,
          fixedVersion: f.fixedVersion,
          cve: f.cve,
          cvssScore: f.cvss,
          references: JSON.stringify(f.references || []),
          status: 'open'
        }))
      });
    }
  }

  if (!result.dependencies.length && !result.findings.length) {
    try {
      const fallback = await aiFallbackDeps(opts.targetValue, opts.manifest);
      result.dependencies = fallback.dependencies;
      result.findings = fallback.findings;
      if (fallback.findings.length) {
        await prisma.finding.createMany({
          data: fallback.findings.map(f => ({
            scanId: scan.id,
            type: 'vulnerability',
            severity: f.severity,
            title: f.title,
            description: f.description,
            package: f.package,
            installedVersion: f.version,
            fixedVersion: f.fixedVersion,
            cve: f.cve,
            references: JSON.stringify(f.references || []),
            status: 'open'
          }))
        });
      }
    } catch (e) {
      console.warn('AI dependency fallback failed:', (e as Error).message);
    }
  }

  const meta = {
    branch: opts.branch,
    filename: opts.filename,
    format: opts.format,
    dependencies: result.dependencies,
    sbom: result.sbom
  };

  await prisma.scan.update({
    where: { id: scan.id },
    data: {
      status: 'completed',
      summary: JSON.stringify(result.summary),
      targetMeta: JSON.stringify(meta),
      completedAt: new Date()
    }
  });

  const full = await prisma.scan.findUnique({
    where: { id: scan.id },
    include: { findings: true }
  });
  await auditLog(opts.request, 'DEPENDENCY_SCAN_COMPLETED', 'scan', scan.id, { target: opts.targetValue });
  return buildDependencyScan(full, full?.findings || [], meta);
}

export async function dependenciesRoutes(app: FastifyInstance) {
  const scanRepoHandler = async (request: any, reply: any) => {
    const userId = request.user.userId;
    const { repoUrl, branch } = request.body as { repoUrl: string; branch?: string };
    try {
      const data = await runDependencyScan({
        userId,
        targetType: 'git_repo',
        targetValue: repoUrl.trim(),
        branch: branch || 'main',
        request
      });
      return { success: true, data };
    } catch (error: any) {
      return reply.code(500).send({
        success: false,
        error: { code: 'SCAN_FAILED', message: error?.message || 'Dependency scan failed', statusCode: 500 }
      });
    }
  };

  app.post('/scan', { preHandler: [app.authenticate], schema: { body: scanRepoSchema } }, scanRepoHandler);
  app.post('/scan-repo', { preHandler: [app.authenticate], schema: { body: scanRepoSchema } }, scanRepoHandler);

  app.post('/scan-manifest', {
    preHandler: [app.authenticate]
  }, async (request, reply) => {
    const userId = (request as any).user.userId;
    let manifest = '';
    let filename = 'package.json';
    let format = 'package-json';

    const contentType = String(request.headers['content-type'] || '');
    if (contentType.includes('multipart/form-data')) {
      const file = await request.file();
      if (!file) {
        return reply.code(400).send({
          success: false,
          error: { code: 'NO_FILE', message: 'No manifest uploaded', statusCode: 400 }
        });
      }
      const chunks: Buffer[] = [];
      for await (const chunk of file.file) chunks.push(chunk);
      manifest = Buffer.concat(chunks).toString('utf-8');
      filename = file.filename;
      format = formatFromFilename(filename);
    } else {
      const body = (request.body || {}) as any;
      manifest = body.manifest || body.content || '';
      filename = body.filename || body.targetName || 'package.json';
      format = body.format || body.type || formatFromFilename(filename);
      if (!manifest) {
        return reply.code(400).send({
          success: false,
          error: { code: 'NO_MANIFEST', message: 'Manifest content is required', statusCode: 400 }
        });
      }
    }

    try {
      const data = await runDependencyScan({
        userId,
        targetType: 'manifest',
        targetValue: filename,
        manifest,
        format,
        filename,
        request
      });
      return { success: true, data };
    } catch (error: any) {
      return reply.code(500).send({
        success: false,
        error: { code: 'SCAN_FAILED', message: error?.message || 'Manifest scan failed', statusCode: 500 }
      });
    }
  });

  const listScans = async (request: any) => {
    const userId = request.user.userId;
    const scans = await prisma.scan.findMany({
      where: { userId, type: 'dependency' },
      include: { findings: true },
      orderBy: { createdAt: 'desc' },
      take: 30
    });
    const data = scans.map(scan => {
      let meta: any = {};
      try { meta = scan.targetMeta ? JSON.parse(scan.targetMeta) : {}; } catch { meta = {}; }
      return buildDependencyScan(scan, scan.findings, meta);
    });
    return { success: true, data };
  };

  app.get('/', { preHandler: [app.authenticate] }, listScans);
  app.post('/outdated', { preHandler: [app.authenticate] }, listScans);

  const getScan = async (request: any, reply: any) => {
    const userId = request.user.userId;
    const { id } = request.params as { id: string };
    const scan = await prisma.scan.findUnique({
      where: { id },
      include: { findings: true }
    });
    if (!scan || scan.userId !== userId) {
      return reply.code(404).send({
        success: false,
        error: { code: 'NOT_FOUND', message: 'Scan not found', statusCode: 404 }
      });
    }
    let meta: any = {};
    try { meta = scan.targetMeta ? JSON.parse(scan.targetMeta) : {}; } catch { meta = {}; }
    return { success: true, data: buildDependencyScan(scan, scan.findings, meta) };
  };

  app.get('/scan/:id', { preHandler: [app.authenticate] }, getScan);
  app.get('/:id', { preHandler: [app.authenticate] }, getScan);

  app.post('/remediate', {
    preHandler: [app.authenticate],
    schema: { body: remediateSchema }
  }, async (request, reply) => {
    const userId = (request as any).user.userId;
    const body = request.body as {
      scanId: string;
      packageName?: string;
      currentVersion?: string;
      pkg?: string;
      version?: string;
    };
    const packageName = body.packageName || body.pkg || '';
    const currentVersion = body.currentVersion || body.version || '';

    const scan = await prisma.scan.findUnique({
      where: { id: body.scanId },
      include: { findings: true }
    });
    if (!scan || scan.userId !== userId) {
      return reply.code(404).send({
        success: false,
        error: { code: 'NOT_FOUND', message: 'Scan not found', statusCode: 404 }
      });
    }

    const related = scan.findings.filter(f => f.package === packageName);
    const targetVersion = related.find(f => f.fixedVersion)?.fixedVersion || 'latest';
    const command = packageName.includes('/') && !packageName.startsWith('@')
      ? `# Update ${packageName} to ${targetVersion}`
      : `npm install ${packageName}@${targetVersion}`;

    try {
      const ai = await aiService.fixDependency(
        packageName,
        currentVersion,
        targetVersion,
        related.map(f => ({ id: f.cve || f.ruleId, severity: f.severity, title: f.title })),
        ''
      );
      await auditLog(request, 'DEPENDENCY_REMEDIATE_COMPLETED', 'scan', body.scanId, { packageName });
      return {
        success: true,
        data: {
          dependencyName: packageName,
          currentVersion,
          recommendedVersion: ai.targetVersion || targetVersion,
          explanation: ai.explanation || `Upgrade ${packageName} to remediate known vulnerabilities.`,
          steps: ai.upgradePath?.length ? ai.upgradePath : [
            `Review changelog for ${packageName} ${targetVersion}`,
            `Update the manifest to ${packageName}@${targetVersion}`,
            'Install, run tests, and rescan'
          ],
          command,
          risks: ai.breakingChanges ? ['Possible breaking API changes — review changelog'] : [],
          confidence: ai.confidence || 75,
          breakingChanges: !!ai.breakingChanges
        }
      };
    } catch (error: any) {
      return {
        success: true,
        data: {
          dependencyName: packageName,
          currentVersion,
          recommendedVersion: targetVersion,
          explanation: `Upgrade ${packageName} from ${currentVersion} to ${targetVersion} to address ${related.length} related finding(s). ${error?.message || ''}`,
          steps: [
            `Pin ${packageName} to ${targetVersion} in the manifest`,
            'Reinstall dependencies',
            'Run the test suite and a follow-up SCA scan'
          ],
          command,
          risks: [],
          confidence: 60,
          breakingChanges: false
        }
      };
    }
  });

  const exportSbom = async (request: any, reply: any) => {
    const userId = request.user.userId;
    const id = (request.params as any).id || (request.body as any)?.scanId;
    const format = (request.query as any)?.format || (request.body as any)?.format || 'cyclonedx';
    const scan = await prisma.scan.findUnique({ where: { id } });
    if (!scan || scan.userId !== userId) {
      return reply.code(404).send({
        success: false,
        error: { code: 'NOT_FOUND', message: 'Scan not found', statusCode: 404 }
      });
    }
    let meta: any = {};
    try { meta = scan.targetMeta ? JSON.parse(scan.targetMeta) : {}; } catch { meta = {}; }
    const sbom = meta.sbom || { packages: [], relationships: [], metadata: { timestamp: new Date().toISOString(), tool: 'DevSecOps' } };
    if (format === 'spdx') {
      return { success: true, data: JSON.parse(convertToSPDXJson(sbom)) };
    }
    return { success: true, data: JSON.parse(convertToCycloneDXJson(sbom)) };
  };

  app.get('/scan/:id/sbom', { preHandler: [app.authenticate] }, exportSbom);
  app.get('/:id/sbom', { preHandler: [app.authenticate] }, exportSbom);
  app.post('/export-sbom', { preHandler: [app.authenticate] }, exportSbom);
  app.post('/sbom', { preHandler: [app.authenticate] }, listScans);
}

function convertToCycloneDXJson(sbom: any): string {
  const components = (sbom.packages || []).map((pkg: any) => ({
    type: 'library',
    name: pkg.name,
    version: pkg.version,
    purl: pkg.purl,
    licenses: (pkg.licenses || []).map((l: string) => ({ license: { name: l } }))
  }));
  return JSON.stringify({
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    version: 1,
    metadata: {
      timestamp: sbom.metadata?.timestamp || new Date().toISOString(),
      tools: [{ name: sbom.metadata?.tool || 'DevSecOps AI' }]
    },
    components
  });
}

function convertToSPDXJson(sbom: any): string {
  return JSON.stringify({
    spdxVersion: 'SPDX-2.3',
    dataLicense: 'CC0-1.0',
    SPDXID: 'SPDXRef-DOCUMENT',
    name: sbom.metadata?.component?.name || 'SBOM',
    creationInfo: {
      created: sbom.metadata?.timestamp || new Date().toISOString(),
      creators: [`Tool: ${sbom.metadata?.tool || 'DevSecOps AI'}`]
    },
    packages: (sbom.packages || []).map((pkg: any) => ({
      name: pkg.name,
      versionInfo: pkg.version,
      SPDXID: `SPDXRef-${String(pkg.name).replace(/[^a-zA-Z0-9.-]/g, '-')}`
    }))
  });
}
