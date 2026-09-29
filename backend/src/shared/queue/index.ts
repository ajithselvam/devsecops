import { Queue, Worker, Job, QueueEvents } from 'bullmq';
import { config } from '../config';
import { prisma } from '../database';
import { aiService } from '../ai';
import { logger } from '../utils/logger';
import { JobType, JobStatus } from '@devsecops/shared/types';

// Import scanner modules
import { scanDockerfile, fixDockerfile, scanDockerImage, fixDockerImage } from '../../modules/dockerfile/scanners';
import { scanKubernetes, fixKubernetes, generateKubernetes } from '../../modules/kubernetes/scanners';
import { scanJenkinsfile, fixJenkinsfile, generateJenkinsfile } from '../../modules/jenkins/scanners';
import { scanGitHubRepo, fixGitHubCode } from '../../modules/github/scanners';
import { scanDependencies, remediateDependency, generateSBOM } from '../../modules/dependencies/scanners';
import { investigateLogs, searchLogs, parseLogFile } from '../../modules/logs/scanners';

interface JobData {
  type: JobType;
  input: Record<string, unknown>;
  userId: string;
  scanId?: string;
  jobId?: string;
}

/**
 * The queue needs Redis. When it is not configured we keep the HTTP API fully
 * usable (auth, scans listing, logs, settings, SBOM export) and fail only the
 * endpoints that actually enqueue work, instead of log-spamming reconnect
 * errors from a worker that can never reach Redis.
 */
export const queueAvailable = (): boolean => config.QUEUE_ENABLED;

let queue: Queue<JobData> | null = null;
let queueEvents: QueueEvents | null = null;

function redisConnection() {
  return {
    host: new URL(config.REDIS_URL).hostname,
    port: parseInt(new URL(config.REDIS_URL).port || '6379')
  };
}

if (config.QUEUE_ENABLED) {
  queue = new Queue<JobData>('devsecops-jobs', {
    connection: redisConnection(),
    defaultJobOptions: {
      removeOnComplete: 100,
      removeOnFail: 50,
      attempts: 3,
      backoff: { type: 'exponential', delay: 5000 }
    }
  });

  queueEvents = new QueueEvents('devsecops-jobs', {
    connection: redisConnection()
  });

  queueEvents.on('completed', async ({ jobId, returnvalue }) => {
    console.log('Queue event: completed', jobId);
    await updateJobStatus(jobId, 'completed', 100, 'Completed', returnvalue as any);
  });

  queueEvents.on('failed', async ({ jobId, failedReason }) => {
    console.log('Queue event: failed', jobId, failedReason);
    await updateJobStatus(jobId, 'failed', 0, 'Failed', undefined, failedReason);
  });

  queueEvents.on('progress', async ({ jobId, data }) => {
    if (data && typeof data === 'object' && 'progress' in data) {
      const progressData = data as { progress: number; currentStep?: string };
      await updateJobProgress(jobId, progressData.progress, progressData.currentStep || '');
    }
  });
}

export class QueueUnavailableError extends Error {
  constructor() {
    super('Background job processing is unavailable: no Redis configured (set REDIS_URL and QUEUE_ENABLED=true)');
    this.name = 'QueueUnavailableError';
  }
}

export async function initializeQueue(): Promise<void> {
  if (!config.QUEUE_ENABLED) {
    logger.warn('Job queue disabled: no Redis configured. Scan/fix endpoints will return 503.');
    return;
  }
  // Create workers for each job type
  const worker = new Worker<JobData>(
    'devsecops-jobs',
    async (job) => await processJob(job),
    {
      connection: redisConnection(),
      concurrency: config.QUEUE_CONCURRENCY
    }
  );

  worker.on('error', (err) => logger.error({ err }, 'Queue worker error'));
  logger.info('Job queue workers started');
}

export async function shutdownQueue(): Promise<void> {
  await queue?.close();
  await queueEvents?.close();
}

export async function createJob(data: JobData, priority: 'low' | 'normal' | 'high' = 'normal'): Promise<string> {
  if (!queue) throw new QueueUnavailableError();

  // Create Job record first
  const prismaJob = await prisma.job.create({
    data: {
      type: data.type,
      status: 'queued',
      input: JSON.stringify(data.input),
      userId: data.userId,
      scanId: data.scanId
    }
  });

  // Add to BullMQ queue with the job ID
  const job = await queue.add(data.type, { ...data, jobId: prismaJob.id }, {
    priority: priority === 'high' ? 10 : priority === 'low' ? 1 : 5,
    jobId: prismaJob.id
  });

  return job.id!;
}

export async function getJobStatus(jobId: string): Promise<any> {
  if (!queue) return null;
  const job = await queue.getJob(jobId);
  if (!job) return null;

  const state = await job.getState();
  const progress = job.progress;

  return {
    id: job.id,
    type: job.name,
    status: state,
    progress: typeof progress === 'number' ? progress : 0,
    data: job.data,
    returnvalue: job.returnvalue,
    failedReason: job.failedReason,
    createdAt: new Date(job.timestamp).toISOString(),
    processedAt: job.processedOn ? new Date(job.processedOn).toISOString() : null,
    finishedAt: job.finishedOn ? new Date(job.finishedOn).toISOString() : null
  };
}

export async function cancelJob(jobId: string): Promise<boolean> {
  if (!queue) return false;
  const job = await queue.getJob(jobId);
  if (job) {
    await job.remove();
    await updateJobStatus(jobId, 'cancelled', 0, 'Cancelled');
    return true;
  }
  return false;
}

async function updateJobStatus(
  jobId: string,
  status: JobStatus,
  progress: number,
  currentStep: string,
  output?: any,
  error?: string
): Promise<void> {
  await prisma.job.updateMany({
    where: { id: jobId },
    data: {
      status,
      progress,
      currentStep,
      output,
      error,
      completedAt: ['completed', 'failed', 'cancelled'].includes(status) ? new Date() : null
    }
  });
}

async function updateJobProgress(jobId: string, progress: number, currentStep: string): Promise<void> {
  await prisma.job.updateMany({
    where: { id: jobId },
    data: { progress, currentStep }
  });
}

async function processJob(job: Job<JobData>): Promise<any> {
  const { type, input, userId, scanId: scanIdFromJob, jobId: prismaJobId } = job.data as JobData & { jobId?: string };
  const scanId = scanIdFromJob || '';
  const jobId = prismaJobId || job.id!;

  await prisma.job.update({
    where: { id: jobId },
    data: { status: 'running', startedAt: new Date() }
  });

  try {
    let result: any;
    const i = input as Record<string, unknown>;

    const content = String(i.content ?? '');
    const imageName = String(i.imageName ?? '');
    const dockerfile = String(i.dockerfile ?? '');
    const repoUrl = String(i.repoUrl ?? '');
    const branch = String(i.branch ?? 'main');
    const token = String(i.token ?? '');
    const fileContent = String(i.fileContent ?? '');
    const surroundingContext = String(i.surroundingContext ?? '');
    const question = String(i.question ?? '');
    const query = String(i.query ?? '');
    const filePath = String(i.filePath ?? '');
    const scanIdParam = String(i.scanId ?? '');
    const packageName = String(i.packageName ?? '');
    const currentVersion = String(i.currentVersion ?? '');
    const format = String(i.format ?? 'cyclonedx') as 'cyclonedx' | 'spdx';

    switch (type) {
      case 'dockerfile_scan':
        result = await scanDockerfile(content, job, scanId);
        break;
      case 'dockerfile_fix':
        result = await fixDockerfile(content, (i.findings as any[]) || [], job);
        break;
      case 'docker_image_scan':
        result = await scanDockerImage(imageName, job, scanId);
        break;
      case 'docker_image_fix':
        result = await fixDockerImage(dockerfile, (i.vulnerabilities as any[]) || [], job);
        break;
      case 'kubernetes_scan':
        result = await scanKubernetes(content, job, scanId);
        break;
      case 'kubernetes_fix':
        result = await fixKubernetes(content, (i.findings as any[]) || [], job);
        break;
      case 'kubernetes_generate':
        result = await generateKubernetes(i.spec as any, job);
        break;
      case 'jenkinsfile_scan':
        result = await scanJenkinsfile(content, job, scanId);
        break;
      case 'jenkinsfile_fix':
        result = await fixJenkinsfile(content, (i.findings as any[]) || [], job);
        break;
      case 'jenkinsfile_generate':
        result = await generateJenkinsfile(i.spec as any, job);
        break;
      case 'github_repo_scan':
        result = await scanGitHubRepo(repoUrl, branch, token, job, scanId, (i.scanTypes as string[]) || undefined);
        break;
      case 'github_code_fix':
        result = await fixGitHubCode(i.finding as any, fileContent, surroundingContext, job);
        break;
      case 'log_investigation':
        result = await investigateLogs(question, (i.logEntries as any[]) || [], i.context, job);
        break;
      case 'log_search':
        result = await searchLogs(query, (i.logFiles as string[]) || [], i.options as { caseSensitive?: boolean; regex?: boolean; before?: number; after?: number } || {}, job);
        break;
      case 'log_parse':
        result = await parseLogFile(filePath, job);
        break;
      case 'dependency_scan':
        result = await scanDependencies(i as any, job, scanId);
        break;
      case 'dependency_fix':
        result = await remediateDependency(scanIdParam, packageName, currentVersion, job);
        break;
      case 'sbom_generation':
        result = await generateSBOM(scanIdParam, format, job);
        break;
      default:
        throw new Error(`Unknown job type: ${type}`);
    }

    // Create scan record if applicable
    if (scanId) {
      await prisma.scan.update({
        where: { id: scanId },
        data: {
          status: 'completed',
          summary: result.summary,
          completedAt: new Date()
        }
      });
    }

    return result;
  } catch (error) {
    logger.error({ err: error, jobId: job.id, type }, 'Job processing failed');

    if (scanId) {
      await prisma.scan.update({
        where: { id: scanId },
        data: { status: 'failed', completedAt: new Date() }
      });
    }

    throw error;
  }
}