import axios from 'axios';
import { restoreSession } from '../lib/session';

export const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json'
  }
});

/**
 * The API authenticates with the InsForge access token. The SDK owns the session
 * (including silent refresh), so the interceptor just reads the current token
 * before each request and asks the SDK to recover an expired one on a 401.
 */
api.interceptors.request.use(async (config) => {
  const token = await restoreSession();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

let refreshInFlight: Promise<string | null> | null = null;

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    if (error.response?.status === 401 && originalRequest && !originalRequest._retry) {
      originalRequest._retry = true;

      // restoreSession() refreshes through the SDK when the token has expired.
      refreshInFlight ??= restoreSession().finally(() => {
        refreshInFlight = null;
      });

      const token = await refreshInFlight;
      if (token) {
        originalRequest.headers.Authorization = `Bearer ${token}`;
        return api(originalRequest);
      }

      window.location.href = '/login';
    }

    return Promise.reject(error);
  }
);

// Auth (sign-in lives in InsForge; these endpoints only serve the profile)
export const authApi = {
  logout: () => api.post('/auth/logout'),
  me: () => api.get('/auth/me'),
  updateMe: (data: Partial<{ name: string; avatarUrl: string; theme: string; sidebarCollapsed: boolean; language: string }>) =>
    api.patch('/auth/me', data)
};

// Dockerfile
export const dockerfileApi = {
  analyze: (content: string) => api.post('/dockerfile/analyze', { content }),
  fix: (content: string, issues?: any[], options?: any) => api.post('/dockerfile/fix', { content, issues, options }),
  validate: (content: string) => api.post('/dockerfile/validate', { content })
};

// Docker Image
export const dockerApi = {
  scan: (image: string) => api.post('/docker/scan', { image }),
  fix: (image: string, vulnerabilities: any[], dockerfile?: string, options?: any) =>
    api.post('/docker/fix', { image, vulnerabilities, dockerfile, options }),
  build: (dockerfile: string, tag: string, options?: any) => api.post('/docker/build', { dockerfile, tag, options }),
  push: (image: string, registry?: string) => api.post('/docker/push', { image, registry }),
  pull: (image: string) => api.post('/docker/pull', { image }),
  listImages: () => api.get('/docker/images'),
  removeImage: (image: string) => api.delete('/docker/images', { data: { image } })
};

// Kubernetes
export const kubernetesApi = {
  analyze: (content: string) => api.post('/kubernetes/analyze', { content }),
  fix: (content: string, issues?: any[], options?: any) => api.post('/kubernetes/fix', { content, issues, options }),
  generate: (resourceType: string, config: any) => api.post('/kubernetes/generate', { resourceType, config }),
  validate: (content: string) => api.post('/kubernetes/validate', { content }),
  apply: (content: string, cluster?: string) => api.post('/kubernetes/apply', { content, cluster })
};

// Jenkins
export const jenkinsApi = {
  analyze: (content: string) => api.post('/jenkins/analyze', { content }),
  fix: (content: string, issues?: any[], options?: any) => api.post('/jenkins/fix', { content, issues, options }),
  generate: (config: any) => api.post('/jenkins/generate', { config }),
  validate: (content: string) => api.post('/jenkins/validate', { content }),
  servers: {
    list: () => api.get('/jenkins/servers'),
    add: (data: { name: string; url: string; credentials: any }) => api.post('/jenkins/servers', data),
    test: (id: string) => api.post(`/jenkins/servers/${id}/test`),
    remove: (id: string) => api.delete(`/jenkins/servers/${id}`),
    jobs: (id: string) => api.get(`/jenkins/servers/${id}/jobs`),
    trigger: (id: string, jobName: string, params?: any) => api.post(`/jenkins/servers/${id}/jobs/${jobName}/trigger`, params),
    buildLog: (id: string, jobName: string, buildNumber: number) => api.get(`/jenkins/servers/${id}/jobs/${jobName}/builds/${buildNumber}/log`)
  }
};

// GitHub
export const githubApi = {
  status: () => api.get('/github/status'),
  connect: (token: string) => api.post('/github/connect', { token }),
  disconnect: () => api.delete('/github/connect'),
  repositories: () => api.get('/github/repositories'),
  scan: (repoUrl: string, branch: string, scanTypes?: string[]) => api.post('/github/scan', { repoUrl, branch, scanTypes }),
  scanStatus: (scanId: string) => api.get(`/github/scans/${scanId}`),
  scanResults: (scanId: string) => api.get(`/github/scans/${scanId}/results`),
  fix: (findingId: string, repoId: string, branch: string, fixType: string, scanId?: string) =>
    api.post('/github/fix', { findingId, repoId, branch, fixType, scanId }),
  createPR: (data: { repoId: string; branch: string; title: string; body: string; changes: any[] }) =>
    api.post('/github/pr', data)
};

// Logs
export const logsApi = {
  upload: (file: File, onProgress?: (progress: number) => void) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post('/logs/upload', formData, {
      transformRequest: [(data, headers) => {
        if (headers) {
          delete (headers as any)['Content-Type'];
          delete (headers as any)['content-type'];
        }
        return data;
      }],
      onUploadProgress: (e) => onProgress?.(Math.round((e.loaded * 100) / (e.total || 1)))
    });
  },
  list: () => api.get('/logs'),
  delete: (id: string) => api.delete(`/logs/${id}`),
  search: (query: string, logFileIds: string[], timeRange?: any, level?: string[], service?: string[]) =>
    api.post('/logs/search', { query, logFileIds, timeRange, level, service, levels: level, services: service }),
  investigate: (question: string, logFileIds: string[], timeRange?: any) =>
    api.post('/logs/investigate', { question, logFileIds, timeRange }),
  getEntries: (id: string, params?: { limit?: number; offset?: number; level?: string }) =>
    api.get(`/logs/${id}/entries`, { params })
};

// Dependencies
export const dependenciesApi = {
  list: () => api.get('/dependencies'),
  scan: (repoUrl: string, branch?: string) => api.post('/dependencies/scan', { repoUrl, branch }),
  scanRepo: (repoUrl: string, branch: string) =>
    api.post('/dependencies/scan', { repoUrl, branch }),
  scanManifest: (content: string, type: string, filename?: string) =>
    api.post('/dependencies/scan-manifest', { manifest: content, content, format: type, type, filename }),
  fix: (pkg: string, currentVersion: string, targetVersion: string, manifestPath: string, vulnerabilityIds?: string[]) =>
    api.post('/dependencies/remediate', { pkg, packageName: pkg, currentVersion, targetVersion, manifestPath, vulnerabilityIds }),
  upload: (file: File, onProgress?: (progress: number) => void) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post('/dependencies/scan-manifest', formData, {
      transformRequest: [(data, headers) => {
        if (headers) {
          delete (headers as any)['Content-Type'];
          delete (headers as any)['content-type'];
        }
        return data;
      }],
      onUploadProgress: (e) => onProgress?.(Math.round((e.loaded * 100) / (e.total || 1)))
    });
  },
  getOutdated: () => api.get('/dependencies'),
  generateSBOM: (repoUrl: string, branch?: string) => api.post('/dependencies/scan', { repoUrl, branch }),
  get: (id: string) => api.get(`/dependencies/${id}`),
  remediate: (scanId: string, pkg: string, version: string) =>
    api.post('/dependencies/remediate', { scanId, pkg, version, packageName: pkg, currentVersion: version }),
  exportSBOM: (scanId: string, format: string) => api.get(`/dependencies/${scanId}/sbom`, { params: { format } })
};

// Scans / History
export const scansApi = {
  list: (params?: { page?: number; pageSize?: number; type?: string; status?: string }) =>
    api.get('/scans', { params }),
  get: (id: string) => api.get(`/scans/${id}`),
  delete: (id: string) => api.delete(`/scans/${id}`),
  getStats: () => api.get('/scans/stats'),
  batchDelete: (ids: string[]) => api.delete('/scans/batch', { data: { ids } }),
  export: (params?: { format?: string; type?: string[]; status?: string[]; search?: string }) =>
    api.post('/scans/export', params)
};

// Jobs
export const jobsApi = {
  list: (params?: { page?: number; pageSize?: number; status?: string; type?: string }) =>
    api.get('/jobs', { params }),
  get: (id: string) => api.get(`/jobs/${id}`),
  cancel: (id: string) => api.post(`/jobs/${id}/cancel`),
  retry: (id: string) => api.post(`/jobs/${id}/retry`)
};

// Settings
export const settingsApi = {
  get: () => api.get('/settings'),
  update: (data: any) => api.patch('/settings', data),
  testAI: () => api.post('/settings/test-ai'),
  testDocker: () => api.post('/settings/test-docker'),
  testGitHub: () => api.post('/settings/test-github'),
  testJenkins: (serverId: string) => api.post('/settings/test-jenkins', { serverId }),
  getAll: () => api.get('/settings'),
  createApiKey: (data: { name: string; expiresAt?: string }) => api.post('/settings/api-keys', data),
  revokeApiKey: (id: string) => api.delete(`/settings/api-keys/${id}`),
  exportData: () => api.get('/settings/export'),
  importData: (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    return api.post('/settings/import', formData, { headers: { 'Content-Type': 'multipart/form-data' } });
  },
  deleteAccount: () => api.delete('/settings/account'),
  updateProfile: (data: any) => api.patch('/auth/me', data)
};

// AI
export const aiApi = {
  test: () => api.get('/ai/test'),
  ask: (data: { prompt: string; context?: string; model?: string; temperature?: number; maxTokens?: number; systemPrompt?: string }) =>
    api.post('/ai/ask', data),
  fix: (data: { code: string; language?: string; finding: any; context?: string }) =>
    api.post('/ai/fix', data),
  explain: (data: { code: string; language?: string; focus?: string }) =>
    api.post('/ai/explain', data),
  models: () => api.get('/ai/models')
};

// Notifications
export const notificationsApi = {
  list: (params?: { page?: number; pageSize?: number; read?: boolean }) =>
    api.get('/notifications', { params }),
  markRead: (id: string) => api.patch(`/notifications/${id}/read`),
  markAllRead: () => api.patch('/notifications/read-all'),
  delete: (id: string) => api.delete(`/notifications/${id}`)
};