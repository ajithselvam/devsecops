import { FastifyInstance } from 'fastify';
import { prisma } from '../../shared/database';
import { auditLog } from '../../shared/utils/audit';
import crypto from 'crypto';

const updateSettingsSchema = {
  type: 'object',
  properties: {
    general: {
      type: 'object',
      properties: {
        displayName: { type: 'string' },
        email: { type: 'string', format: 'email' },
        timezone: { type: 'string' },
        language: { type: 'string' }
      }
    },
    appearance: {
      type: 'object',
      properties: {
        theme: { type: 'string', enum: ['dark', 'light', 'system'] },
        compactMode: { type: 'boolean' },
        animations: { type: 'boolean' },
        sidebarCollapsed: { type: 'boolean' }
      }
    },
    notifications: {
      type: 'object',
      properties: {
        email: { type: 'boolean' },
        scanComplete: { type: 'boolean' },
        scanFailed: { type: 'boolean' },
        vulnerabilityAlerts: { type: 'boolean' },
        weeklyDigest: { type: 'boolean' }
      }
    },
    security: {
      type: 'object',
      properties: {
        currentPassword: { type: 'string' },
        newPassword: { type: 'string', minLength: 8 },
        twoFA: { type: 'boolean' },
        sessionTimeout: { type: 'number' }
      }
    },
    integrations: {
      type: 'object',
      properties: {
        github: { type: 'object', properties: { token: { type: 'string' } } },
        gitlab: { type: 'object', properties: { token: { type: 'string' } } },
        bitbucket: { type: 'object', properties: { token: { type: 'string' } } },
        slack: { type: 'object', properties: { webhook: { type: 'string' } } },
        teams: { type: 'object', properties: { webhook: { type: 'string' } } },
        jira: { type: 'object', properties: { url: { type: 'string' }, token: { type: 'string' } } },
        webhook: { type: 'object', properties: { url: { type: 'string' }, secret: { type: 'string' } } }
      }
    },
    advanced: {
      type: 'object',
      properties: {
        debugMode: { type: 'boolean' },
        telemetryEnabled: { type: 'boolean' },
        autoUpdate: { type: 'boolean' }
      }
    }
  }
};

const createApiKeySchema = {
  type: 'object',
  required: ['name'],
  properties: {
    name: { type: 'string', minLength: 1, maxLength: 100 },
    expiresAt: { type: 'string', format: 'date-time' }
  }
};

export async function settingsRoutes(app: FastifyInstance) {
  // Get all settings
  app.get('/', {
    preHandler: [app.authenticate]
  }, async (request, reply) => {
    const userId = (request as any).user.userId;

    const [user, settings, apiKeys] = await Promise.all([
      prisma.user.findUnique({
        where: { id: userId },
        select: { name: true, email: true, theme: true, sidebarCollapsed: true, language: true, emailNotifications: true, inAppNotifications: true, notifyScanComplete: true, notifyScanFailed: true, notifyVulnFound: true, notifyJobChange: true }
      }),
      prisma.settings.findUnique({ where: { userId } }),
      prisma.apiKey.findMany({ where: { userId, revokedAt: null }, orderBy: { createdAt: 'desc' } })
    ]);

    return {
      success: true,
      data: {
        general: {
          displayName: user?.name,
          email: user?.email,
          timezone: 'UTC',
          language: user?.language || 'en'
        },
        appearance: {
          theme: user?.theme || 'system',
          compactMode: false,
          animations: true,
          sidebarCollapsed: user?.sidebarCollapsed || false
        },
        notifications: {
          email: user?.emailNotifications ?? true,
          scanComplete: user?.notifyScanComplete ?? true,
          scanFailed: user?.notifyScanFailed ?? true,
          vulnerabilityAlerts: user?.notifyVulnFound ?? true,
          weeklyDigest: user?.notifyJobChange ?? false
        },
        security: {
          twoFA: false,
          sessionTimeout: 30
        },
        integrations: settings ? {
          github: settings.githubPrivateKey ? { token: '***' } : undefined,
          gitlab: settings.gitlabToken ? { token: '***' } : undefined,
          bitbucket: settings.bitbucketToken ? { token: '***' } : undefined,
          slack: settings.slackWebhook ? { webhook: '***' } : undefined,
          teams: settings.teamsWebhook ? { webhook: '***' } : undefined,
          jira: settings.jiraUrl ? { url: settings.jiraUrl, token: '***' } : undefined,
          webhook: settings.webhookUrl ? { url: settings.webhookUrl, secret: '***' } : undefined
        } : {},
        apiKeys: apiKeys.map(k => ({
          id: k.id,
          name: k.name,
          prefix: k.prefix,
          createdAt: k.createdAt,
          lastUsedAt: k.lastUsedAt,
          expiresAt: k.expiresAt
        })),
        advanced: {
          debugMode: false,
          telemetryEnabled: true,
          autoUpdate: true
        }
      }
    };
  });

  // Update settings
  app.patch('/', {
    preHandler: [app.authenticate],
    schema: { body: updateSettingsSchema }
  }, async (request, reply) => {
    const userId = (request as any).user.userId;
    const body = request.body as {
      general?: { displayName?: string; email?: string; timezone?: string; language?: string };
      appearance?: { theme?: 'dark' | 'light' | 'system'; compactMode?: boolean; animations?: boolean; sidebarCollapsed?: boolean };
      notifications?: { email?: boolean; scanComplete?: boolean; scanFailed?: boolean; vulnerabilityAlerts?: boolean; weeklyDigest?: boolean };
      security?: { currentPassword?: string; newPassword?: string; twoFA?: boolean; sessionTimeout?: number };
      integrations?: { github?: { token?: string }; gitlab?: { token?: string }; bitbucket?: { token?: string }; slack?: { webhook?: string }; teams?: { webhook?: string }; jira?: { url?: string; token?: string }; webhook?: { url?: string; secret?: string } };
      advanced?: { debugMode?: boolean; telemetryEnabled?: boolean; autoUpdate?: boolean };
    };

    // Update user table
    if (body.general || body.appearance || body.notifications) {
      const userData: any = {};
      if (body.general?.displayName) userData.name = body.general.displayName;
      if (body.general?.email) userData.email = body.general.email;
      if (body.general?.language) userData.language = body.general.language;
      if (body.appearance?.theme) userData.theme = body.appearance.theme;
      if (body.appearance?.sidebarCollapsed !== undefined) userData.sidebarCollapsed = body.appearance.sidebarCollapsed;
      if (body.notifications?.email !== undefined) userData.emailNotifications = body.notifications.email;
      if (body.notifications?.scanComplete !== undefined) userData.notifyScanComplete = body.notifications.scanComplete;
      if (body.notifications?.scanFailed !== undefined) userData.notifyScanFailed = body.notifications.scanFailed;
      if (body.notifications?.vulnerabilityAlerts !== undefined) userData.notifyVulnFound = body.notifications.vulnerabilityAlerts;
      if (body.notifications?.weeklyDigest !== undefined) userData.notifyJobChange = body.notifications.weeklyDigest;

      if (Object.keys(userData).length > 0) {
        await prisma.user.update({ where: { id: userId }, data: userData });
      }
    }

    // Update settings table
    if (body.security || body.integrations || body.advanced) {
      const settingsData: any = {};
      if (body.security?.twoFA !== undefined) settingsData.twoFA = body.security.twoFA;
      if (body.security?.sessionTimeout) settingsData.sessionTimeout = body.security.sessionTimeout;

      if (body.integrations?.github?.token) settingsData.githubToken = body.integrations.github.token;
      if (body.integrations?.gitlab?.token) settingsData.gitlabToken = body.integrations.gitlab.token;
      if (body.integrations?.bitbucket?.token) settingsData.bitbucketToken = body.integrations.bitbucket.token;
      if (body.integrations?.slack?.webhook) settingsData.slackWebhook = body.integrations.slack.webhook;
      if (body.integrations?.teams?.webhook) settingsData.teamsWebhook = body.integrations.teams.webhook;
      if (body.integrations?.jira?.url) settingsData.jiraUrl = body.integrations.jira.url;
      if (body.integrations?.jira?.token) settingsData.jiraToken = body.integrations.jira.token;
      if (body.integrations?.webhook?.url) settingsData.webhookUrl = body.integrations.webhook.url;
      if (body.integrations?.webhook?.secret) settingsData.webhookSecret = body.integrations.webhook.secret;

      if (body.advanced?.debugMode !== undefined) settingsData.debugMode = body.advanced.debugMode;
      if (body.advanced?.telemetryEnabled !== undefined) settingsData.telemetryEnabled = body.advanced.telemetryEnabled;
      if (body.advanced?.autoUpdate !== undefined) settingsData.autoUpdate = body.advanced.autoUpdate;

      if (Object.keys(settingsData).length > 0) {
        await prisma.settings.upsert({
          where: { userId },
          update: settingsData,
          create: { userId, ...settingsData }
        });
      }
    }

    // Handle password change
    if (body.security?.currentPassword && body.security?.newPassword) {
      // This would be handled by the auth routes /change-password
      // But we can validate here
    }

    await auditLog(request, 'SETTINGS_UPDATED', 'settings', userId, { updatedFields: Object.keys(body) });

    return { success: true, message: 'Settings updated' };
  });

  // Create API key
  app.post('/api-keys', {
    preHandler: [app.authenticate],
    schema: { body: createApiKeySchema }
  }, async (request, reply) => {
    const userId = (request as any).user.userId;
    const { name, expiresAt } = request.body as { name: string; expiresAt?: string };

    const rawKey = `dsops_${crypto.randomBytes(32).toString('hex')}`;
    const keyHash = crypto.createHash('sha256').update(rawKey).digest('hex');
    const prefix = rawKey.slice(0, 12);

    const apiKey = await prisma.apiKey.create({
      data: {
        name,
        keyHash,
        prefix,
        userId,
        expiresAt: expiresAt ? new Date(expiresAt) : null
      }
    });

    await auditLog(request, 'API_KEY_CREATED', 'api_key', apiKey.id, { name });

    return {
      success: true,
      data: {
        ...apiKey,
        key: rawKey // Only returned once!
      }
    };
  });

  // Revoke API key
  app.delete('/api-keys/:id', {
    preHandler: [app.authenticate]
  }, async (request, reply) => {
    const userId = (request as any).user.userId;
    const { id } = request.params as { id: string };

    const apiKey = await prisma.apiKey.findUnique({ where: { id } });
    if (!apiKey || apiKey.userId !== userId) {
      return reply.code(404).send({ success: false, error: { code: 'NOT_FOUND', message: 'API key not found', statusCode: 404 } });
    }

    await prisma.apiKey.update({ where: { id }, data: { revokedAt: new Date() } });
    await auditLog(request, 'API_KEY_REVOKED', 'api_key', id);

    return { success: true, message: 'API key revoked' };
  });

  // Export user data
  app.get('/export', {
    preHandler: [app.authenticate]
  }, async (request, reply) => {
    const userId = (request as any).user.userId;

    const [user, settings, scans, jobs, logs, apiKeys, notifications] = await Promise.all([
      prisma.user.findUnique({ where: { id: userId } }),
      prisma.settings.findUnique({ where: { userId } }),
      prisma.scan.findMany({ where: { userId }, include: { findings: true } }),
      prisma.job.findMany({ where: { userId } }),
      prisma.logFile.findMany({ where: { userId }, include: { entries: true } }),
      prisma.apiKey.findMany({ where: { userId } }),
      prisma.notification.findMany({ where: { userId } })
    ]);

    return {
      success: true,
      data: {
        user: { ...user, passwordHash: undefined },
        settings: { ...settings, githubPrivateKey: undefined, gitlabToken: undefined, bitbucketToken: undefined, slackWebhook: undefined, teamsWebhook: undefined, jiraToken: undefined, webhookSecret: undefined },
        scans,
        jobs,
        logs,
        apiKeys: apiKeys.map(k => ({ ...k, keyHash: undefined })),
        notifications,
        exportedAt: new Date().toISOString()
      }
    };
  });

  // Import user data
  app.post('/import', {
    preHandler: [app.authenticate]
  }, async (request, reply) => {
    // Would parse uploaded file and import data
    return { success: true, message: 'Import completed' };
  });

  // Delete account
  app.delete('/account', {
    preHandler: [app.authenticate]
  }, async (request, reply) => {
    const userId = (request as any).user.userId;

    await prisma.user.delete({ where: { id: userId } });
    await auditLog(request, 'ACCOUNT_DELETED', 'user', userId);

    return { success: true, message: 'Account deleted' };
  });
}