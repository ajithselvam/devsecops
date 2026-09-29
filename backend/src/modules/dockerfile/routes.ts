import { FastifyInstance } from 'fastify';
import { prisma } from '../../shared/database';
import { createJob } from '../../shared/queue';
import { auditLog } from '../../shared/utils/audit';
import { aiService } from '../../shared/ai';
import { scanDockerfile } from './scanners';

const scanSchema = {
  type: 'object',
  required: ['content'],
  properties: {
    content: { type: 'string', minLength: 1 },
    targetName: { type: 'string' },
    fix: { type: 'boolean', default: false }
  }
};

const analyzeSchema = {
  type: 'object',
  required: ['content'],
  properties: {
    content: { type: 'string', minLength: 1 }
  }
};

const fixSchema = {
  type: 'object',
  required: ['content'],
  properties: {
    content: { type: 'string', minLength: 1 },
    issues: { type: 'array' },
    options: { type: 'object' }
  }
};

const validateSchema = {
  type: 'object',
  required: ['content'],
  properties: {
    content: { type: 'string', minLength: 1 }
  }
};

const fixFromScanSchema = {
  type: 'object',
  required: ['scanId'],
  properties: {
    scanId: { type: 'string', format: 'uuid' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          type: { type: 'string' },
          severity: { type: 'string' },
          title: { type: 'string' },
          description: { type: 'string' },
          file: { type: 'string' },
          line: { type: 'number' },
          code: { type: 'string' },
          ruleId: { type: 'string' },
          remediation: { type: 'object' }
        }
      }
    }
  }
};

const imageScanSchema = {
  type: 'object',
  required: ['imageName'],
  properties: {
    imageName: { type: 'string', minLength: 1 },
    targetName: { type: 'string' }
  }
};

const imageFixSchema = {
  type: 'object',
  required: ['scanId', 'dockerfile'],
  properties: {
    scanId: { type: 'string', format: 'uuid' },
    dockerfile: { type: 'string', minLength: 1 },
    vulnerabilities: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          type: { type: 'string' },
          severity: { type: 'string' },
          title: { type: 'string' },
          description: { type: 'string' },
          package: { type: 'string' },
          version: { type: 'string' },
          fixedVersion: { type: 'string' }
        }
      }
    }
  }
};

async function analyzeDockerfileSync(content: string): Promise<any> {
  // Run the sync scan using the scanner directly (no queue)
  const mockJob = {
    id: 'sync-scan',
    updateProgress: async () => {},
    data: { type: 'dockerfile_scan', input: { content }, userId: '', scanId: '' }
  } as any;

  const result = await scanDockerfile(content, mockJob, '');

  // Convert findings to the format frontend expects
  const issues = result.findings.map(f => ({
    id: f.id,
    type: f.type,
    severity: f.severity,
    message: f.description,
    line: f.line,
    column: f.column,
    rule: f.ruleId || f.type,
    fixable: f.fixable || false,
    suggestion: f.fixable && f.fixedVersion
      ? `Update to version ${f.fixedVersion}`
      : undefined
  }));

  return {
    issues,
    summary: result.summary,
    sbom: result.sbom
  };
}

async function fixDockerfileSync(content: string, issues: any[], options?: any): Promise<any> {
  // Use AI to generate a fixed Dockerfile
  const prompt = `
You are a Docker security expert. Fix the following Dockerfile issues and return ONLY the fixed Dockerfile content with no markdown, no explanations, no code fences.

Original Dockerfile:
${content}

Issues to fix:
${issues.map((i: any, idx: number) => `${idx + 1}. [${i.severity.toUpperCase()}] Line ${i.line}: ${i.message}${i.suggestion ? ` - Suggestion: ${i.suggestion}` : ''}`).join('\n')}

Rules:
- Output ONLY raw Dockerfile lines. Do not wrap in markdown or code blocks.
- Apply all fixable issues.
- Keep the Dockerfile functional.
`;

  try {
    const aiResult = await aiService.ask({
      prompt,
      systemPrompt: 'You are a Docker security expert. Always respond with raw Dockerfile content only — no markdown, no code fences, no explanations.',
      temperature: 0.1,
      maxTokens: 4096
    });

    // Strip any markdown code fences the AI may have added despite instructions
    let fixedDockerfile = aiResult.response.trim();
    // Remove opening fence: ```dockerfile, ``` dockerfile, ```
    fixedDockerfile = fixedDockerfile.replace(/^```[a-zA-Z]*\s*\n?/, '');
    // Remove closing fence
    fixedDockerfile = fixedDockerfile.replace(/\n?```\s*$/, '');
    fixedDockerfile = fixedDockerfile.trim();

    if (!fixedDockerfile) {
      throw new Error('AI returned an empty Dockerfile response');
    }

    // Generate changes summary
    const changes = issues.filter((i: any) => i.fixable).map((issue: any) => ({
      findingId: issue.id,
      type: 'ai_fix',
      description: `Fixed: ${issue.message}`,
      line: issue.line
    }));

    return {
      fixedDockerfile,
      changes,
      securityImprovements: issues
        .filter((i: any) => i.fixable)
        .map((i: any) => `Resolved ${i.severity} issue: ${i.message}`),
      explanation: `AI analyzed ${issues.length} issues and applied fixes. ${issues.filter((i: any) => i.fixable).length} issues were fixable and have been addressed.`
    };
  } catch (error) {
    console.error('AI fix failed:', error);

    return {
      fixedDockerfile: content,
      changes: [],
      securityImprovements: [],
      explanation: `AI fix unavailable: ${error instanceof Error ? error.message : 'Unknown error'}. Returned original Dockerfile.`
    };
  }
}

export async function dockerfileRoutes(app: FastifyInstance) {
  // Sync analyze - returns results immediately (frontend expects this)
  app.post('/analyze', {
    preHandler: [app.authenticate],
    schema: { body: analyzeSchema }
  }, async (request, reply) => {
    const { content } = request.body as { content: string };

    try {
      const result = await analyzeDockerfileSync(content);
      return { success: true, data: result };
    } catch (error: any) {
      console.error('Analyze error:', error);
      return reply.code(500).send({ success: false, error: { code: 'ANALYZE_FAILED', message: error.message || 'Analysis failed', statusCode: 500 } });
    }
  });

  // Sync fix - returns fixed dockerfile immediately (frontend expects this)
  app.post('/fix', {
    preHandler: [app.authenticate],
    schema: { body: fixSchema }
  }, async (request, reply) => {
    const { content, issues, options } = request.body as { content: string; issues?: any[]; options?: any };

    try {
      const result = await fixDockerfileSync(content, issues || [], options);
      return { success: true, data: result };
    } catch (error: any) {
      console.error('Fix error:', error);
      return reply.code(500).send({ success: false, error: { code: 'FIX_FAILED', message: error.message || 'Fix failed', statusCode: 500 } });
    }
  });

  // Validate Dockerfile syntax
  app.post('/validate', {
    preHandler: [app.authenticate],
    schema: { body: validateSchema }
  }, async (request, reply) => {
    const { content } = request.body as { content: string };

    // Basic validation - check for common syntax issues
    const lines = content.split('\n');
    const errors: string[] = [];
    const warnings: string[] = [];

    if (!content.trim()) {
      errors.push('Dockerfile is empty');
    }

    let hasFrom = false;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (line.startsWith('FROM ')) {
        hasFrom = true;
        // Check for latest tag
        if (line.includes(':latest') || line.endsWith('FROM')) {
          warnings.push(`Line ${i + 1}: Using 'latest' tag is not recommended for production`);
        }
      }
      // Check for USER root
      if (line === 'USER root') {
        warnings.push(`Line ${i + 1}: Running as root user is a security risk`);
      }
    }

    if (!hasFrom) {
      errors.push('Dockerfile must have a FROM instruction');
    }

    return {
      success: true,
      data: {
        valid: errors.length === 0,
        errors,
        warnings
      }
    };
  });

  // Scan Dockerfile (async job-based)
  app.post('/scan', {
    preHandler: [app.authenticate],
    schema: { body: scanSchema }
  }, async (request, reply) => {
    const userId = (request as any).user.userId;
    const { content, targetName, fix } = request.body as { content: string; targetName?: string; fix?: boolean };

    // Create scan record
    const scan = await prisma.scan.create({
      data: {
        type: 'dockerfile',
        status: 'pending',
        targetType: 'dockerfile',
        targetValue: targetName || 'Dockerfile',
        targetMeta: JSON.stringify({ content }),
        userId
      }
    });

    // Create job
    const jobId = await createJob({
      type: 'dockerfile_scan',
      input: { content },
      userId,
      scanId: scan.id
    });

    await prisma.scan.update({
      where: { id: scan.id },
      data: { jobId: jobId }
    });

    await auditLog(request, 'DOCKERFILE_SCAN_STARTED', 'scan', scan.id, { targetName });

    return { success: true, data: { scanId: scan.id, jobId: jobId } };
  });

  // Scan Docker Image
  app.post('/scan-image', {
    preHandler: [app.authenticate],
    schema: { body: imageScanSchema }
  }, async (request, reply) => {
    const userId = (request as any).user.userId;
    const { imageName, targetName } = request.body as { imageName: string; targetName?: string };

    // Create scan record
    const scan = await prisma.scan.create({
      data: {
        type: 'docker_image',
        status: 'pending',
        targetType: 'docker_image',
        targetValue: targetName || imageName,
        targetMeta: JSON.stringify({ imageName }),
        userId
      }
    });

    // Create job
    const jobId = await createJob({
      type: 'docker_image_scan',
      input: { imageName },
      userId,
      scanId: scan.id
    });

    await prisma.scan.update({
      where: { id: scan.id },
      data: { jobId }
    });

    await auditLog(request, 'DOCKER_IMAGE_SCAN_STARTED', 'scan', scan.id, { imageName });

    return { success: true, data: { scanId: scan.id, jobId } };
  });

  // Fix Dockerfile from scan results
  app.post('/fix-from-scan', {
    preHandler: [app.authenticate],
    schema: { body: fixFromScanSchema }
  }, async (request, reply) => {
    const userId = (request as any).user.userId;
    const { scanId, findings } = request.body as { scanId: string; findings?: any[] };

    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: { findings: true }
    });

    if (!scan || scan.userId !== userId) {
      return reply.code(404).send({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found', statusCode: 404 } });
    }

    const dockerfile = (scan.targetMeta as any)?.content || '';

    const jobId = await createJob({
      type: 'dockerfile_fix',
      input: { content: dockerfile, findings: findings || scan.findings },
      userId,
      scanId
    });

    await auditLog(request, 'DOCKERFILE_FIX_STARTED', 'scan', scanId);

    return { success: true, data: { jobId } };
  });

  // Fix Docker Image (base image upgrade)
  app.post('/fix-image', {
    preHandler: [app.authenticate],
    schema: { body: imageFixSchema }
  }, async (request, reply) => {
    const userId = (request as any).user.userId;
    const { scanId, dockerfile, vulnerabilities } = request.body as { scanId: string; dockerfile: string; vulnerabilities?: any[] };

    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      include: { findings: true }
    });

    if (!scan || scan.userId !== userId) {
      return reply.code(404).send({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found', statusCode: 404 } });
    }

    const jobId = await createJob({
      type: 'docker_image_fix',
      input: { dockerfile, vulnerabilities: vulnerabilities || scan.findings },
      userId,
      scanId
    });

    await auditLog(request, 'DOCKER_IMAGE_FIX_STARTED', 'scan', scanId);

    return { success: true, data: { jobId } };
  });

  // Get scan results
  app.get('/scan/:id', {
    preHandler: [app.authenticate]
  }, async (request, reply) => {
    const userId = (request as any).user.userId;
    const { id } = request.params as { id: string };

    const scan = await prisma.scan.findUnique({
      where: { id },
      include: { findings: { orderBy: [{ severity: 'desc' }, { createdAt: 'desc' }] } }
    });

    if (!scan || scan.userId !== userId) {
      return reply.code(404).send({ success: false, error: { code: 'NOT_FOUND', message: 'Scan not found', statusCode: 404 } });
    }

    return { success: true, data: scan };
  });
}