"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.QueueUnavailableError = exports.queueAvailable = void 0;
exports.initializeQueue = initializeQueue;
exports.shutdownQueue = shutdownQueue;
exports.createJob = createJob;
exports.getJobStatus = getJobStatus;
exports.cancelJob = cancelJob;
const bullmq_1 = require("bullmq");
const config_1 = require("../config");
const database_1 = require("../database");
const logger_1 = require("../utils/logger");
// Import scanner modules
const scanners_1 = require("../../modules/dockerfile/scanners");
const scanners_2 = require("../../modules/kubernetes/scanners");
const scanners_3 = require("../../modules/jenkins/scanners");
const scanners_4 = require("../../modules/github/scanners");
const scanners_5 = require("../../modules/dependencies/scanners");
const scanners_6 = require("../../modules/logs/scanners");
/**
 * The queue needs Redis. When it is not configured we keep the HTTP API fully
 * usable (auth, scans listing, logs, settings, SBOM export) and fail only the
 * endpoints that actually enqueue work, instead of log-spamming reconnect
 * errors from a worker that can never reach Redis.
 */
const queueAvailable = () => config_1.config.QUEUE_ENABLED;
exports.queueAvailable = queueAvailable;
let queue = null;
let queueEvents = null;
function redisConnection() {
    return {
        host: new URL(config_1.config.REDIS_URL).hostname,
        port: parseInt(new URL(config_1.config.REDIS_URL).port || '6379')
    };
}
if (config_1.config.QUEUE_ENABLED) {
    queue = new bullmq_1.Queue('devsecops-jobs', {
        connection: redisConnection(),
        defaultJobOptions: {
            removeOnComplete: 100,
            removeOnFail: 50,
            attempts: 3,
            backoff: { type: 'exponential', delay: 5000 }
        }
    });
    queueEvents = new bullmq_1.QueueEvents('devsecops-jobs', {
        connection: redisConnection()
    });
    queueEvents.on('completed', async ({ jobId, returnvalue }) => {
        console.log('Queue event: completed', jobId);
        await updateJobStatus(jobId, 'completed', 100, 'Completed', returnvalue);
    });
    queueEvents.on('failed', async ({ jobId, failedReason }) => {
        console.log('Queue event: failed', jobId, failedReason);
        await updateJobStatus(jobId, 'failed', 0, 'Failed', undefined, failedReason);
    });
    queueEvents.on('progress', async ({ jobId, data }) => {
        if (data && typeof data === 'object' && 'progress' in data) {
            const progressData = data;
            await updateJobProgress(jobId, progressData.progress, progressData.currentStep || '');
        }
    });
}
class QueueUnavailableError extends Error {
    constructor() {
        super('Background job processing is unavailable: no Redis configured (set REDIS_URL and QUEUE_ENABLED=true)');
        this.name = 'QueueUnavailableError';
    }
}
exports.QueueUnavailableError = QueueUnavailableError;
async function initializeQueue() {
    if (!config_1.config.QUEUE_ENABLED) {
        logger_1.logger.warn('Job queue disabled: no Redis configured. Scan/fix endpoints will return 503.');
        return;
    }
    // Create workers for each job type
    const worker = new bullmq_1.Worker('devsecops-jobs', async (job) => await processJob(job), {
        connection: redisConnection(),
        concurrency: config_1.config.QUEUE_CONCURRENCY
    });
    worker.on('error', (err) => logger_1.logger.error({ err }, 'Queue worker error'));
    logger_1.logger.info('Job queue workers started');
}
async function shutdownQueue() {
    await queue?.close();
    await queueEvents?.close();
}
async function createJob(data, priority = 'normal') {
    if (!queue)
        throw new QueueUnavailableError();
    // Create Job record first
    const prismaJob = await database_1.prisma.job.create({
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
    return job.id;
}
async function getJobStatus(jobId) {
    if (!queue)
        return null;
    const job = await queue.getJob(jobId);
    if (!job)
        return null;
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
async function cancelJob(jobId) {
    if (!queue)
        return false;
    const job = await queue.getJob(jobId);
    if (job) {
        await job.remove();
        await updateJobStatus(jobId, 'cancelled', 0, 'Cancelled');
        return true;
    }
    return false;
}
async function updateJobStatus(jobId, status, progress, currentStep, output, error) {
    await database_1.prisma.job.updateMany({
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
async function updateJobProgress(jobId, progress, currentStep) {
    await database_1.prisma.job.updateMany({
        where: { id: jobId },
        data: { progress, currentStep }
    });
}
async function processJob(job) {
    const { type, input, userId, scanId: scanIdFromJob, jobId: prismaJobId } = job.data;
    const scanId = scanIdFromJob || '';
    const jobId = prismaJobId || job.id;
    await database_1.prisma.job.update({
        where: { id: jobId },
        data: { status: 'running', startedAt: new Date() }
    });
    try {
        let result;
        const i = input;
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
        const format = String(i.format ?? 'cyclonedx');
        switch (type) {
            case 'dockerfile_scan':
                result = await (0, scanners_1.scanDockerfile)(content, job, scanId);
                break;
            case 'dockerfile_fix':
                result = await (0, scanners_1.fixDockerfile)(content, i.findings || [], job);
                break;
            case 'docker_image_scan':
                result = await (0, scanners_1.scanDockerImage)(imageName, job, scanId);
                break;
            case 'docker_image_fix':
                result = await (0, scanners_1.fixDockerImage)(dockerfile, i.vulnerabilities || [], job);
                break;
            case 'kubernetes_scan':
                result = await (0, scanners_2.scanKubernetes)(content, job, scanId);
                break;
            case 'kubernetes_fix':
                result = await (0, scanners_2.fixKubernetes)(content, i.findings || [], job);
                break;
            case 'kubernetes_generate':
                result = await (0, scanners_2.generateKubernetes)(i.spec, job);
                break;
            case 'jenkinsfile_scan':
                result = await (0, scanners_3.scanJenkinsfile)(content, job, scanId);
                break;
            case 'jenkinsfile_fix':
                result = await (0, scanners_3.fixJenkinsfile)(content, i.findings || [], job);
                break;
            case 'jenkinsfile_generate':
                result = await (0, scanners_3.generateJenkinsfile)(i.spec, job);
                break;
            case 'github_repo_scan':
                result = await (0, scanners_4.scanGitHubRepo)(repoUrl, branch, token, job, scanId, i.scanTypes || undefined);
                break;
            case 'github_code_fix':
                result = await (0, scanners_4.fixGitHubCode)(i.finding, fileContent, surroundingContext, job);
                break;
            case 'log_investigation':
                result = await (0, scanners_6.investigateLogs)(question, i.logEntries || [], i.context, job);
                break;
            case 'log_search':
                result = await (0, scanners_6.searchLogs)(query, i.logFiles || [], i.options || {}, job);
                break;
            case 'log_parse':
                result = await (0, scanners_6.parseLogFile)(filePath, job);
                break;
            case 'dependency_scan':
                result = await (0, scanners_5.scanDependencies)(i, job, scanId);
                break;
            case 'dependency_fix':
                result = await (0, scanners_5.remediateDependency)(scanIdParam, packageName, currentVersion, job);
                break;
            case 'sbom_generation':
                result = await (0, scanners_5.generateSBOM)(scanIdParam, format, job);
                break;
            default:
                throw new Error(`Unknown job type: ${type}`);
        }
        // Create scan record if applicable
        if (scanId) {
            await database_1.prisma.scan.update({
                where: { id: scanId },
                data: {
                    status: 'completed',
                    summary: result.summary,
                    completedAt: new Date()
                }
            });
        }
        return result;
    }
    catch (error) {
        logger_1.logger.error({ err: error, jobId: job.id, type }, 'Job processing failed');
        if (scanId) {
            await database_1.prisma.scan.update({
                where: { id: scanId },
                data: { status: 'failed', completedAt: new Date() }
            });
        }
        throw error;
    }
}
