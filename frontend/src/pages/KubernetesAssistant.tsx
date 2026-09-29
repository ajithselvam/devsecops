import React, { useState, useCallback, useRef } from 'react';
import {
  Upload,
  Download,
  Copy,
  RotateCcw,
  Sparkles,
  Shield,
  AlertTriangle,
  CheckCircle,
  Info,
  FileText,
  Wand2,
  Search,
  Filter,
  Box,
  Network,
  Lock,
  Server
} from 'lucide-react';
import { kubernetesApi } from '../services/api';
import { KubernetesAnalysis, K8sResourceType, KubernetesGeneratorConfig, UUID, ISODateString, Finding } from '@devsecops/shared/types';
import { CodeEditor } from '../components/CodeEditor';
import { DiffViewer } from '../components/DiffViewer';
import { FindingList } from '../components/FindingCard';
import { toast } from 'react-hot-toast';
import { clsx } from 'clsx';

const DEFAULT_YAML = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  labels:
    app: my-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: my-app
  template:
    metadata:
      labels:
        app: my-app
    spec:
      containers:
      - name: my-app
        image: nginx:latest
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: my-app
spec:
  selector:
    app: my-app
  ports:
  - port: 80
    targetPort: 80`;

const SEVERITY_ORDER: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

const RESOURCE_TYPES: K8sResourceType[] = [
  'Deployment', 'Service', 'Ingress', 'ConfigMap', 'Secret', 'StatefulSet',
  'DaemonSet', 'Job', 'CronJob', 'Namespace', 'ServiceAccount', 'Role',
  'RoleBinding', 'NetworkPolicy', 'PersistentVolumeClaim'
];

export function KubernetesAssistant() {
  const [yaml, setYaml] = useState(DEFAULT_YAML);
  const [analysis, setAnalysis] = useState<KubernetesAnalysis | null>(null);
  const [fixedYaml, setFixedYaml] = useState('');
  const [loading, setLoading] = useState(false);
  const [fixing, setFixing] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [viewMode, setViewMode] = useState<'editor' | 'diff' | 'findings'>('editor');
  const [activeTab, setActiveTab] = useState<'fixer' | 'generator'>('fixer');
  const [filterSeverity, setFilterSeverity] = useState<string[]>(['critical', 'high', 'medium', 'low', 'info']);
  const [showOnlyFixable, setShowOnlyFixable] = useState(false);
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Generator form state
  const [genForm, setGenForm] = useState<KubernetesGeneratorConfig>({
    name: 'my-app',
    namespace: 'default',
    image: 'nginx:latest',
    replicas: 3,
    port: 80,
    serviceType: 'ClusterIP',
    ingressEnabled: true,
    ingressHost: 'my-app.example.com',
    cpuRequest: '250m',
    memoryRequest: '256Mi',
    livenessProbe: { enabled: true, path: '/healthz', port: 80, initialDelaySeconds: 30, periodSeconds: 10 },
    readinessProbe: { enabled: true, path: '/readyz', port: 80, initialDelaySeconds: 10, periodSeconds: 5 },
    securityContext: { enabled: true, runAsNonRoot: true, runAsUser: 1000, readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, capabilities: ['DROP_ALL'] }
  });
  const [genResourceType, setGenResourceType] = useState<K8sResourceType>('Deployment');
  const [generatedYaml, setGeneratedYaml] = useState('');

  const handleFileUpload = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      setYaml(e.target?.result as string);
      setAnalysis(null);
      setFixedYaml('');
      setViewMode('editor');
      toast.success('YAML loaded');
    };
    reader.readAsText(file);
    event.target.value = '';
  }, []);

  const handleAnalyze = async () => {
    if (!yaml.trim()) {
      toast.error('Please provide YAML');
      return;
    }
    setLoading(true);
    try {
      const response = await kubernetesApi.analyze(yaml);
      if (response.data.success) {
        setAnalysis(response.data.data);
        toast.success(`Analysis complete: ${response.data.data.issues.length} issues found`);
      } else {
        toast.error(response.data.error?.message || 'Analysis failed');
      }
    } catch (err) {
      toast.error('Failed to analyze YAML');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleFix = async () => {
    if (!analysis) {
      toast.error('Please analyze first');
      return;
    }
    setFixing(true);
    try {
      const response = await kubernetesApi.fix(yaml, analysis.issues);
      if (response.data.success) {
        setFixedYaml(response.data.data.fixedYaml);
        setAnalysis(prev => prev ? {
          ...prev,
          fixedYaml: response.data.data.fixedYaml,
          changes: response.data.data.changes,
          explanation: response.data.data.explanation
        } : null);
        setViewMode('diff');
        toast.success('YAML fixed successfully!');
      } else {
        toast.error(response.data.error?.message || 'Fix failed');
      }
    } catch (err) {
      toast.error('Failed to fix YAML');
      console.error(err);
    } finally {
      setFixing(false);
    }
  };

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      const response = await kubernetesApi.generate(genResourceType, genForm);
      if (response.data.success) {
        setGeneratedYaml(response.data.data.yaml);
        toast.success('YAML generated successfully!');
      } else {
        toast.error(response.data.error?.message || 'Generation failed');
      }
    } catch (err) {
      toast.error('Failed to generate YAML');
      console.error(err);
    } finally {
      setGenerating(false);
    }
  };

  const handleApplyFixed = () => {
    if (fixedYaml) {
      setYaml(fixedYaml);
      setViewMode('editor');
      toast.success('Fixed version applied');
    }
  };

  const handleReset = () => {
    setYaml(DEFAULT_YAML);
    setAnalysis(null);
    setFixedYaml('');
    setViewMode('editor');
    toast.success('Reset to default');
  };

  const handleDownload = () => {
    const content = viewMode === 'editor' ? yaml : fixedYaml || yaml;
    const blob = new Blob([content], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'manifest.yaml';
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Downloaded');
  };

  const handleCopy = () => {
    const content = viewMode === 'editor' ? yaml : fixedYaml || yaml;
    navigator.clipboard.writeText(content);
    toast.success('Copied to clipboard');
  };

  const filteredIssues = analysis?.issues.filter(issue => {
    if (!filterSeverity.includes(issue.severity)) return false;
    if (showOnlyFixable && !issue.fixable) return false;
    return true;
  }) || [];

  const sortedIssues = [...filteredIssues].sort((a, b) =>
    (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0)
  );

  const severityCounts = analysis?.issues.reduce((acc, issue) => {
    acc[issue.severity] = (acc[issue.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>) || {};

  const toggleExpand = (finding: any) => {
    setExpandedFindings(prev => {
      const next = new Set(prev);
      if (next.has(finding.id)) next.delete(finding.id);
      else next.add(finding.id);
      return next;
    });
  };

  const updateGenForm = (path: string, value: any) => {
    setGenForm(prev => {
      const keys = path.split('.');
      const updated = { ...prev } as any;
      let current = updated;
      for (let i = 0; i < keys.length - 1; i++) {
        current[keys[i]] = { ...current[keys[i]] };
        current = current[keys[i]];
      }
      current[keys[keys.length - 1]] = value;
      return updated;
    });
  };

  const input = "input w-full px-3 py-2 bg-background-tertiary border border-border rounded-lg text-foreground text-sm focus:border-accent-blue focus:ring-1 focus:ring-accent-blue";

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Kubernetes YAML AI Assistant</h1>
          <p className="text-foreground-secondary mt-1">
            Validate, fix, and generate production-ready Kubernetes manifests
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button className="btn-secondary" onClick={() => fileInputRef.current?.click()}>
            <Upload className="w-4 h-4" />
            Upload
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".yaml,.yml"
            onChange={handleFileUpload}
            className="hidden"
          />
          <button className="btn-secondary" onClick={handleDownload}>
            <Download className="w-4 h-4" />
            Download
          </button>
          <button className="btn-secondary" onClick={handleCopy}>
            <Copy className="w-4 h-4" />
            Copy
          </button>
          <button className="btn-secondary" onClick={handleReset}>
            <RotateCcw className="w-4 h-4" />
            Reset
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="tabs">
        <button
          className={clsx('tab', activeTab === 'fixer' && 'tab-active')}
          onClick={() => setActiveTab('fixer')}
        >
          <Shield className="w-4 h-4" />
          YAML Fixer
        </button>
        <button
          className={clsx('tab', activeTab === 'generator' && 'tab-active')}
          onClick={() => setActiveTab('generator')}
        >
          <Wand2 className="w-4 h-4" />
          Generator
        </button>
      </div>

      {activeTab === 'fixer' ? (
        <>
          {/* Toolbar */}
          <div className="card p-4">
            <div className="flex flex-wrap items-center gap-4">
              <div className="tabs">
                <button className={clsx('tab', viewMode === 'editor' && 'tab-active')} onClick={() => setViewMode('editor')}>
                  <FileText className="w-4 h-4" />
                  Editor
                </button>
                {analysis && (
                  <>
                    <button className={clsx('tab', viewMode === 'diff' && 'tab-active')} onClick={() => setViewMode('diff')}>
                      <Search className="w-4 h-4" />
                      Diff
                    </button>
                    <button className={clsx('tab', viewMode === 'findings' && 'tab-active')} onClick={() => setViewMode('findings')}>
                      <AlertTriangle className="w-4 h-4" />
                      Findings
                    </button>
                  </>
                )}
              </div>

              <div className="flex-1" />

              {analysis && (
                <div className="flex items-center gap-4">
                  <Filter className="w-4 h-4 text-foreground-muted" />
                  <select
                    className="input py-1.5 px-3 text-sm w-auto"
                    multiple
                    value={filterSeverity}
                    onChange={(e) => {
                      const selected = Array.from(e.target.selectedOptions).map(o => o.value);
                      setFilterSeverity(selected);
                    }}
                  >
                    {['critical', 'high', 'medium', 'low', 'info'].map((s: any) => (
                      <option key={s} value={s} className="capitalize">
                        {s} ({severityCounts[s] || 0})
                      </option>
                    ))}
                  </select>
                  <label className="flex items-center gap-2 text-sm text-foreground-secondary">
                    <input
                      type="checkbox"
                      checked={showOnlyFixable}
                      onChange={(e) => setShowOnlyFixable(e.target.checked)}
                      className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue"
                    />
                    Fixable only
                  </label>
                </div>
              )}

              <div className="flex items-center gap-2">
                <button className="btn-primary" onClick={handleAnalyze} disabled={loading || !yaml.trim()}>
                  {loading ? (
                    <>
                      <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <Shield className="w-4 h-4" />
                      Analyze
                    </>
                  )}
                </button>
                {analysis && !fixedYaml && (
                  <button className="btn-primary" onClick={handleFix} disabled={fixing}>
                    {fixing ? (
                      <>
                        <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                        Fixing...
                      </>
                    ) : (
                      <>
                        <Sparkles className="w-4 h-4" />
                        AI Fix
                      </>
                    )}
                  </button>
                )}
                {fixedYaml && viewMode !== 'editor' && (
                  <button className="btn-secondary" onClick={handleApplyFixed}>
                    <CheckCircle className="w-4 h-4" />
                    Apply Fix
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Content */}
          {viewMode === 'editor' && (
            <div className="card p-0 overflow-hidden">
              <CodeEditor
                value={yaml}
                onChange={(value: string | undefined) => setYaml(value || '')}
                language="yaml"
                fileName="manifest.yaml"
                maxHeight={500}
                placeholder="Paste or write your Kubernetes YAML here..."
              />
            </div>
          )}

          {viewMode === 'diff' && fixedYaml && analysis && (
            <div className="card p-0 overflow-hidden">
              {analysis.explanation && (
                <div className="p-4 bg-background-tertiary/50 border-b border-border">
                  <div className="flex items-start gap-3">
                    <Info className="w-5 h-5 text-accent-blue flex-shrink-0 mt-0.5" />
                    <div className="prose prose-sm text-foreground-secondary max-w-none">
                      {analysis.explanation.split('\n').map((para, i) => (
                        <p key={i} className="mb-2">{para}</p>
                      ))}
                    </div>
                  </div>
                </div>
              )}
              <DiffViewer
                original={yaml}
                fixed={fixedYaml}
                changes={analysis.changes || []}
                onApplyFixed={handleApplyFixed}
                onReset={handleReset}
              />
            </div>
          )}

          {viewMode === 'findings' && analysis && (
            <div className="card p-0 overflow-hidden">
              <FindingList
                findings={sortedIssues.map(f => ({
                  id: f.id as UUID,
                  scanId: 'kubernetes' as UUID,
                  type: f.type as Finding['type'],
                  severity: f.severity,
                  title: f.message,
                  description: f.suggestion || f.message,
                  file: f.resource,
                  ruleId: f.rule,
                  fixable: f.fixable,
                  remediation: f.fixable ? {
                    available: true,
                    type: 'patch' as const,
                    description: f.suggestion || 'AI will generate a fix',
                    steps: ['Run AI Fix to generate corrected YAML'],
                    confidence: 85,
                    fixedContent: fixedYaml || undefined
                  } : undefined,
                  status: 'open' as const,
                  createdAt: new Date().toISOString() as ISODateString
                }))}
                expandedIds={expandedFindings}
                onToggleExpand={toggleExpand}
                showActions={false}
                emptyMessage="No issues found matching current filters"
              />
            </div>
          )}

          {/* Severity Summary */}
          {analysis && (
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              {['critical', 'high', 'medium', 'low', 'info'].map(sev => (
                <div
                  key={sev}
                  className={clsx('card p-4 text-center', `border-l-4 border-severity-${sev}`)}
                >
                  <p className="text-3xl font-bold" style={{ color: `var(--color-severity-${sev})` }}>
                    {severityCounts[sev] || 0}
                  </p>
                  <p className="text-sm text-foreground-secondary capitalize">{sev}</p>
                </div>
              ))}
            </div>
          )}
        </>
      ) : (
        // Generator Tab
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Generator Form */}
          <div className="card">
            <h2 className="text-lg font-semibold text-foreground mb-4 flex items-center gap-2">
              <Wand2 className="w-5 h-5 text-accent-purple" />
              Generate Kubernetes YAML
            </h2>

            <div className="space-y-4">
              {/* Resource Type */}
              <div>
                <label className="label">Resource Type</label>
                <select
                  className={input}
                  value={genResourceType}
                  onChange={(e) => setGenResourceType(e.target.value as K8sResourceType)}
                >
                  {RESOURCE_TYPES.map(type => (
                    <option key={type} value={type}>{type}</option>
                  ))}
                </select>
              </div>

              {/* Name */}
              <div>
                <label className="label">Application Name</label>
                <input
                  className={input}
                  value={genForm.name}
                  onChange={(e) => updateGenForm('name', e.target.value)}
                  placeholder="my-app"
                />
              </div>

              {/* Image */}
              <div>
                <label className="label">Container Image</label>
                <input
                  className={input}
                  value={genForm.image}
                  onChange={(e) => updateGenForm('image', e.target.value)}
                  placeholder="nginx:latest"
                />
              </div>

              {/* Replicas & Port */}
              <div className="grid grid-cols-2 gap-4">
                {['Deployment', 'StatefulSet', 'DaemonSet'].includes(genResourceType) && (
                  <div>
                    <label className="label">Replicas</label>
                    <input
                      type="number"
                      className={input}
                      value={genForm.replicas}
                      onChange={(e) => updateGenForm('replicas', parseInt(e.target.value) || 1)}
                      min={1}
                    />
                  </div>
                )}
                <div>
                  <label className="label">Container Port</label>
                  <input
                    type="number"
                    className={input}
                    value={genForm.port}
                    onChange={(e) => updateGenForm('port', parseInt(e.target.value) || 80)}
                    min={1}
                  />
                </div>
              </div>

              {/* Service Type */}
              {['Service', 'Deployment'].includes(genResourceType) && (
                <div>
                  <label className="label">Service Type</label>
                  <select
                    className={input}
                    value={genForm.serviceType}
                    onChange={(e) => updateGenForm('serviceType', e.target.value)}
                  >
                    {['ClusterIP', 'NodePort', 'LoadBalancer'].map(t => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </select>
                </div>
              )}

              {/* Ingress */}
              {['Deployment', 'Service'].includes(genResourceType) && (
                <div className="p-3 bg-background-tertiary rounded-lg">
                  <label className="flex items-center gap-2 text-sm font-medium text-foreground mb-2">
                    <input
                      type="checkbox"
                      checked={genForm.ingressEnabled}
                      onChange={(e) => updateGenForm('ingressEnabled', e.target.checked)}
                      className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue"
                    />
                    <Network className="w-4 h-4" />
                    Enable Ingress
                  </label>
                  {genForm.ingressEnabled && (
                    <div className="mt-2">
                      <label className="label">Ingress Host</label>
                      <input
                        className={input}
                        value={genForm.ingressHost}
                        onChange={(e) => updateGenForm('ingressHost', e.target.value)}
                        placeholder="my-app.example.com"
                      />
                    </div>
                  )}
                </div>
              )}

              {/* Resources */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="label">CPU Request</label>
                  <input
                    className={input}
                    value={genForm.cpuRequest}
                    onChange={(e) => updateGenForm('cpuRequest', e.target.value)}
                    placeholder="250m"
                  />
                </div>
                <div>
                  <label className="label">Memory Request</label>
                  <input
                    className={input}
                    value={genForm.memoryRequest}
                    onChange={(e) => updateGenForm('memoryRequest', e.target.value)}
                    placeholder="256Mi"
                  />
                </div>
              </div>

              {/* Probes */}
              <div className="space-y-3">
                {['Deployment', 'StatefulSet', 'DaemonSet'].includes(genResourceType) && (
                  <>
                    <div className="p-3 bg-background-tertiary rounded-lg">
                      <label className="flex items-center gap-2 text-sm font-medium text-foreground mb-2">
                        <input
                          type="checkbox"
                          checked={genForm.livenessProbe?.enabled}
                          onChange={(e) => updateGenForm('livenessProbe.enabled', e.target.checked)}
                          className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue"
                        />
                        <Server className="w-4 h-4" />
                        Liveness Probe
                      </label>
                      {genForm.livenessProbe?.enabled && (
                        <div className="grid grid-cols-3 gap-2 mt-2">
                          <div>
                            <label className="label text-xs">Path</label>
                            <input className={input} value={genForm.livenessProbe?.path} onChange={(e) => updateGenForm('livenessProbe.path', e.target.value)} />
                          </div>
                          <div>
                            <label className="label text-xs">Port</label>
                            <input type="number" className={input} value={genForm.livenessProbe?.port} onChange={(e) => updateGenForm('livenessProbe.port', parseInt(e.target.value))} />
                          </div>
                          <div>
                            <label className="label text-xs">Initial Delay (s)</label>
                            <input type="number" className={input} value={genForm.livenessProbe?.initialDelaySeconds} onChange={(e) => updateGenForm('livenessProbe.initialDelaySeconds', parseInt(e.target.value))} />
                          </div>
                        </div>
                      )}
                    </div>

                    <div className="p-3 bg-background-tertiary rounded-lg">
                      <label className="flex items-center gap-2 text-sm font-medium text-foreground mb-2">
                        <input
                          type="checkbox"
                          checked={genForm.readinessProbe?.enabled}
                          onChange={(e) => updateGenForm('readinessProbe.enabled', e.target.checked)}
                          className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue"
                        />
                        <Server className="w-4 h-4" />
                        Readiness Probe
                      </label>
                      {genForm.readinessProbe?.enabled && (
                        <div className="grid grid-cols-3 gap-2 mt-2">
                          <div>
                            <label className="label text-xs">Path</label>
                            <input className={input} value={genForm.readinessProbe?.path} onChange={(e) => updateGenForm('readinessProbe.path', e.target.value)} />
                          </div>
                          <div>
                            <label className="label text-xs">Port</label>
                            <input type="number" className={input} value={genForm.readinessProbe?.port} onChange={(e) => updateGenForm('readinessProbe.port', parseInt(e.target.value))} />
                          </div>
                          <div>
                            <label className="label text-xs">Initial Delay (s)</label>
                            <input type="number" className={input} value={genForm.readinessProbe?.initialDelaySeconds} onChange={(e) => updateGenForm('readinessProbe.initialDelaySeconds', parseInt(e.target.value))} />
                          </div>
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>

              {/* Security Context */}
              {['Deployment', 'StatefulSet', 'DaemonSet'].includes(genResourceType) && (
                <div className="p-3 bg-background-tertiary rounded-lg">
                  <label className="flex items-center gap-2 text-sm font-medium text-foreground mb-2">
                    <input
                      type="checkbox"
                      checked={genForm.securityContext?.enabled}
                      onChange={(e) => updateGenForm('securityContext.enabled', e.target.checked)}
                      className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue"
                    />
                    <Lock className="w-4 h-4" />
                    Security Context
                  </label>
                  {genForm.securityContext?.enabled && (
                    <div className="grid grid-cols-2 gap-2 mt-2">
                      <label className="flex items-center gap-2 text-sm text-foreground-secondary">
                        <input
                          type="checkbox"
                          checked={genForm.securityContext?.runAsNonRoot}
                          onChange={(e) => updateGenForm('securityContext.runAsNonRoot', e.target.checked)}
                          className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue"
                        />
                        Run as non-root
                      </label>
                      <label className="flex items-center gap-2 text-sm text-foreground-secondary">
                        <input
                          type="checkbox"
                          checked={genForm.securityContext?.readOnlyRootFilesystem}
                          onChange={(e) => updateGenForm('securityContext.readOnlyRootFilesystem', e.target.checked)}
                          className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue"
                        />
                        Read-only FS
                      </label>
                      <label className="flex items-center gap-2 text-sm text-foreground-secondary">
                        <input
                          type="checkbox"
                          checked={!genForm.securityContext?.allowPrivilegeEscalation}
                          onChange={(e) => updateGenForm('securityContext.allowPrivilegeEscalation', !e.target.checked)}
                          className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue"
                        />
                        No priv escalation
                      </label>
                      <label className="flex items-center gap-2 text-sm text-foreground-secondary">
                        <input
                          type="checkbox"
                          checked={genForm.securityContext?.capabilities?.includes('DROP_ALL')}
                          onChange={(e) => updateGenForm('securityContext.capabilities', e.target.checked ? ['DROP_ALL'] : [])}
                          className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue"
                        />
                        Drop capabilities
                      </label>
                    </div>
                  )}
                </div>
              )}

              <button className="btn-primary w-full" onClick={handleGenerate} disabled={generating}>
                {generating ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Generating...
                  </>
                ) : (
                  <>
                    <Wand2 className="w-4 h-4" />
                    Generate Kubernetes YAML
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Output */}
          <div className="card p-0 overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-border">
              <h3 className="font-medium text-foreground">Generated YAML</h3>
              {generatedYaml && (
                <div className="flex gap-2">
                  <button className="btn-secondary text-sm" onClick={() => navigator.clipboard.writeText(generatedYaml)}>
                    <Copy className="w-3.5 h-3.5" />
                  </button>
                  <button className="btn-secondary text-sm" onClick={() => {
                    const blob = new Blob([generatedYaml], { type: 'text/yaml' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `${genForm.name}.yaml`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}>
                    <Download className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
            </div>
            {generatedYaml ? (
              <CodeEditor
                value={generatedYaml}
                onChange={(value: string | undefined) => setGeneratedYaml(value || '')}
                language="yaml"
                fileName={`${genForm.name}.yaml`}
                maxHeight={500}
                readOnly
              />
            ) : (
              <div className="p-12 text-center text-foreground-secondary">
                <Box className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p>Configure options and click Generate</p>
                <p className="text-sm mt-1">Production-ready YAML will appear here</p>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}