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
  Filter,
  GitBranch,
  Server,
  RefreshCw,
  Search,
  Workflow
} from 'lucide-react';
import { jenkinsApi } from '../services/api';
import { JenkinsfileAnalysis, JenkinsGeneratorConfig, JenkinsServer, UUID, ISODateString, FindingType, Severity } from '@devsecops/shared/types';
import { CodeEditor } from '../components/CodeEditor';
import { DiffViewer } from '../components/DiffViewer';
import { FindingList } from '../components/FindingCard';
import { toast } from 'react-hot-toast';
import { clsx } from 'clsx';

const DEFAULT_JENKINSFILE = `pipeline {
    agent any

    stages {
        stage('Build') {
            steps {
                sh 'npm install'
                sh 'npm run build'
            }
        }
        stage('Test') {
            steps {
                sh 'npm test'
            }
        }
        stage('Deploy') {
            steps {
                sh 'docker build -t myapp .'
                sh 'docker push myapp'
                sh 'kubectl apply -f k8s/'
            }
        }
    }
}`;

const SEVERITY_ORDER: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

export function JenkinsAssistant() {
  const [jenkinsfile, setJenkinsfile] = useState(DEFAULT_JENKINSFILE);
  const [analysis, setAnalysis] = useState<JenkinsfileAnalysis | null>(null);
  const [fixedJenkinsfile, setFixedJenkinsfile] = useState('');
  const [loading, setLoading] = useState(false);
  const [fixing, setFixing] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [viewMode, setViewMode] = useState<'editor' | 'diff' | 'findings'>('editor');
  const [activeTab, setActiveTab] = useState<'fixer' | 'generator' | 'integration'>('fixer');
  const [filterSeverity, setFilterSeverity] = useState<string[]>(['critical', 'high', 'medium', 'low', 'info']);
  const [showOnlyFixable, setShowOnlyFixable] = useState(false);
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());
  const [jenkinsServers] = useState<JenkinsServer[]>([]);
  const [selectedServer] = useState<JenkinsServer | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Generator form
  const [genForm, setGenForm] = useState<JenkinsGeneratorConfig>({
    application: 'nodejs',
    repositoryUrl: 'https://github.com/user/repo',
    buildTool: 'npm',
    testing: true,
    dockerBuild: true,
    securityScan: true,
    dockerPush: true,
    deployment: 'kubernetes',
    environments: ['dev', 'staging', 'production'],
    registryUrl: 'docker.io/myorg',
    kubernetesConfig: {
      name: 'my-app',
      image: 'nginx:latest',
      replicas: 3,
      port: 80,
      cpuRequest: '250m',
      memoryRequest: '256Mi'
    }
  });
  const [generatedJenkinsfile, setGeneratedJenkinsfile] = useState('');

  const handleFileUpload = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (e) => {
      setJenkinsfile(e.target?.result as string);
      setAnalysis(null);
      setFixedJenkinsfile('');
      setViewMode('editor');
      toast.success('Jenkinsfile loaded');
    };
    reader.readAsText(file);
    event.target.value = '';
  }, []);

  const handleAnalyze = async () => {
    if (!jenkinsfile.trim()) {
      toast.error('Please provide a Jenkinsfile');
      return;
    }
    setLoading(true);
    try {
      const response = await jenkinsApi.analyze(jenkinsfile);
      if (response.data.success) {
        setAnalysis(response.data.data);
        toast.success(`Analysis complete: ${response.data.data.issues.length} issues found`);
      } else {
        toast.error(response.data.error?.message || 'Analysis failed');
      }
    } catch (err) {
      toast.error('Failed to analyze Jenkinsfile');
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
      const response = await jenkinsApi.fix(jenkinsfile, analysis.issues);
      if (response.data.success) {
        setFixedJenkinsfile(response.data.data.fixedJenkinsfile);
        setAnalysis(prev => prev ? {
          ...prev,
          fixedJenkinsfile: response.data.data.fixedJenkinsfile,
          changes: response.data.data.changes,
          explanation: response.data.data.explanation
        } : null);
        setViewMode('diff');
        toast.success('Jenkinsfile fixed successfully!');
      } else {
        toast.error(response.data.error?.message || 'Fix failed');
      }
    } catch (err) {
      toast.error('Failed to fix Jenkinsfile');
      console.error(err);
    } finally {
      setFixing(false);
    }
  };

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      const response = await jenkinsApi.generate(genForm);
      if (response.data.success) {
        setGeneratedJenkinsfile(response.data.data.jenkinsfile);
        toast.success('Jenkinsfile generated!');
      } else {
        toast.error(response.data.error?.message || 'Generation failed');
      }
    } catch (err) {
      toast.error('Failed to generate Jenkinsfile');
      console.error(err);
    } finally {
      setGenerating(false);
    }
  };

  const handleApplyFixed = () => {
    if (fixedJenkinsfile) {
      setJenkinsfile(fixedJenkinsfile);
      setViewMode('editor');
      toast.success('Fixed version applied');
    }
  };

  const handleReset = () => {
    setJenkinsfile(DEFAULT_JENKINSFILE);
    setAnalysis(null);
    setFixedJenkinsfile('');
    setViewMode('editor');
    toast.success('Reset to default');
  };

  const handleDownload = () => {
    const content = viewMode === 'editor' ? jenkinsfile : fixedJenkinsfile || jenkinsfile;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'Jenkinsfile';
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Downloaded');
  };

  const handleCopy = () => {
    const content = viewMode === 'editor' ? jenkinsfile : fixedJenkinsfile || jenkinsfile;
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

  const input = "input w-full px-3 py-2 bg-background-tertiary border border-border rounded-lg text-foreground text-sm focus:border-accent-blue focus:ring-1 focus:ring-accent-blue";

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Jenkins AI Assistant</h1>
          <p className="text-foreground-secondary mt-1">
            Fix and generate Jenkins pipelines with AI assistance
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
            accept=".jenkinsfile,Jenkinsfile,.groovy"
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
        <button className={clsx('tab', activeTab === 'fixer' && 'tab-active')} onClick={() => setActiveTab('fixer')}>
          <Shield className="w-4 h-4" />
          Jenkinsfile Fixer
        </button>
        <button className={clsx('tab', activeTab === 'generator' && 'tab-active')} onClick={() => setActiveTab('generator')}>
          <Wand2 className="w-4 h-4" />
          Generator
        </button>
        <button className={clsx('tab', activeTab === 'integration' && 'tab-active')} onClick={() => setActiveTab('integration')}>
          <Server className="w-4 h-4" />
          Integration
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
                <button className="btn-primary" onClick={handleAnalyze} disabled={loading || !jenkinsfile.trim()}>
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
                {analysis && !fixedJenkinsfile && (
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
                {fixedJenkinsfile && viewMode !== 'editor' && (
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
                value={jenkinsfile}
                onChange={(value: string | undefined) => setJenkinsfile(value || '')}
                language="jenkinsfile"
                fileName="Jenkinsfile"
                maxHeight={500}
                placeholder="Paste or write your Jenkinsfile here..."
              />
            </div>
          )}

          {viewMode === 'diff' && fixedJenkinsfile && analysis && (
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
                original={jenkinsfile}
                fixed={fixedJenkinsfile}
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
                  scanId: 'jenkinsfile' as UUID,
                  type: f.type as FindingType,
                  severity: f.severity as Severity,
                  title: f.message,
                  description: f.suggestion || f.message,
                  file: 'Jenkinsfile',
                  line: f.line,
                  ruleId: f.rule,
                  fixable: f.fixable,
                  remediation: f.fixable ? {
                    available: true,
                    type: 'patch' as const,
                    description: f.suggestion || 'AI will generate a fix',
                    steps: ['Run AI Fix to generate corrected Jenkinsfile'],
                    confidence: 85,
                    fixedContent: fixedJenkinsfile || undefined
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
      ) : activeTab === 'generator' ? (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Generator Form */}
          <div className="card">
            <h2 className="text-lg font-semibold text-foreground mb-4 flex items-center gap-2">
              <Wand2 className="w-5 h-5 text-accent-yellow" />
              Generate Jenkinsfile
            </h2>

            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="label">Application</label>
                  <select
                    className={input}
                    value={genForm.application}
                    onChange={(e) => setGenForm({ ...genForm, application: e.target.value as any })}
                  >
                    {['nodejs', 'python', 'java', 'go', 'docker', 'generic'].map(t => (
                      <option key={t} value={t} className="capitalize">{t}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="label">Build Tool</label>
                  <select
                    className={input}
                    value={genForm.buildTool}
                    onChange={(e) => setGenForm({ ...genForm, buildTool: e.target.value as any })}
                  >
                    {['npm', 'maven', 'gradle', 'pip', 'make', 'none'].map(t => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div>
                <label className="label">Repository URL</label>
                <input
                  className={input}
                  value={genForm.repositoryUrl}
                  onChange={(e) => setGenForm({ ...genForm, repositoryUrl: e.target.value })}
                  placeholder="https://github.com/user/repo"
                />
              </div>

              {/* Pipeline Options */}
              <div className="space-y-2">
                <p className="font-medium text-foreground mb-2">Pipeline Stages</p>
                {[
                  { key: 'testing', label: 'Testing', icon: CheckCircle },
                  { key: 'dockerBuild', label: 'Docker Build', icon: Workflow },
                  { key: 'securityScan', label: 'Security Scan', icon: Shield },
                  { key: 'dockerPush', label: 'Docker Push', icon: Upload }
                ].map(({ key, label, icon: Icon }) => (
                  <label key={key} className="flex items-center gap-2 text-sm text-foreground-secondary p-2 bg-background-tertiary rounded-lg">
                    <input
                      type="checkbox"
                      checked={(genForm as any)[key]}
                      onChange={(e) => setGenForm({ ...genForm, [key]: e.target.checked })}
                      className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue"
                    />
                    <Icon className="w-4 h-4" />
                    {label}
                  </label>
                ))}
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="label">Deployment</label>
                  <select
                    className={input}
                    value={genForm.deployment}
                    onChange={(e) => setGenForm({ ...genForm, deployment: e.target.value as any })}
                  >
                    {['kubernetes', 'vm', 'none', 'ecs', 'cloudrun'].map(t => (
                      <option key={t} value={t} className="capitalize">{t}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="label">Registry URL</label>
                  <input
                    className={input}
                    value={genForm.registryUrl}
                    onChange={(e) => setGenForm({ ...genForm, registryUrl: e.target.value })}
                    placeholder="docker.io/myorg"
                  />
                </div>
              </div>

              <div>
                <label className="label">Environments</label>
                <div className="flex gap-2">
                  {['dev', 'staging', 'production'].map(env => (
                    <label key={env} className={clsx(
                      'flex-1 flex items-center justify-center gap-2 p-2 rounded-lg text-sm cursor-pointer transition-colors',
                      genForm.environments.includes(env as any)
                        ? 'bg-accent-blue/20 text-accent-blue border border-accent-blue/30'
                        : 'bg-background-tertiary text-foreground-secondary'
                    )}>
                      <input
                        type="checkbox"
                        checked={genForm.environments.includes(env as any)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setGenForm({ ...genForm, environments: [...genForm.environments, env as any] });
                          } else {
                            setGenForm({ ...genForm, environments: genForm.environments.filter(e2 => e2 !== env) });
                          }
                        }}
                        className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue"
                      />
                      <span className="capitalize">{env}</span>
                    </label>
                  ))}
                </div>
              </div>

              {genForm.deployment === 'kubernetes' && (
                <div className="p-3 bg-background-tertiary rounded-lg space-y-3">
                  <p className="font-medium text-foreground">Kubernetes Config</p>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="label text-xs">App Name</label>
                      <input className={input} value={genForm.kubernetesConfig?.name} onChange={(e) => setGenForm({ ...genForm, kubernetesConfig: { ...genForm.kubernetesConfig!, name: e.target.value } })} />
                    </div>
                    <div>
                      <label className="label text-xs">Image</label>
                      <input className={input} value={genForm.kubernetesConfig?.image} onChange={(e) => setGenForm({ ...genForm, kubernetesConfig: { ...genForm.kubernetesConfig!, image: e.target.value } })} />
                    </div>
                    <div>
                      <label className="label text-xs">Replicas</label>
                      <input type="number" className={input} value={genForm.kubernetesConfig?.replicas} onChange={(e) => setGenForm({ ...genForm, kubernetesConfig: { ...genForm.kubernetesConfig!, replicas: parseInt(e.target.value) } })} />
                    </div>
                    <div>
                      <label className="label text-xs">Port</label>
                      <input type="number" className={input} value={genForm.kubernetesConfig?.port} onChange={(e) => setGenForm({ ...genForm, kubernetesConfig: { ...genForm.kubernetesConfig!, port: parseInt(e.target.value) } })} />
                    </div>
                  </div>
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
                    Generate Jenkinsfile
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Output */}
          <div className="card p-0 overflow-hidden">
            <div className="flex items-center justify-between p-4 border-b border-border">
              <h3 className="font-medium text-foreground">Generated Jenkinsfile</h3>
              {generatedJenkinsfile && (
                <div className="flex gap-2">
                  <button className="btn-secondary text-sm" onClick={() => navigator.clipboard.writeText(generatedJenkinsfile)}>
                    <Copy className="w-3.5 h-3.5" />
                  </button>
                  <button className="btn-secondary text-sm" onClick={() => {
                    const blob = new Blob([generatedJenkinsfile], { type: 'text/plain' });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = 'Jenkinsfile';
                    a.click();
                    URL.revokeObjectURL(url);
                  }}>
                    <Download className="w-3.5 h-3.5" />
                  </button>
                </div>
              )}
            </div>
            {generatedJenkinsfile ? (
              <CodeEditor
                value={generatedJenkinsfile}
                onChange={(value: string | undefined) => setGeneratedJenkinsfile(value || '')}
                language="jenkinsfile"
                fileName="Jenkinsfile"
                maxHeight={500}
                readOnly
              />
            ) : (
              <div className="p-12 text-center text-foreground-secondary">
                <GitBranch className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p>Configure options and click Generate</p>
                <p className="text-sm mt-1">Complete CI/CD pipeline will appear here</p>
              </div>
            )}
          </div>
        </div>
      ) : (
        // Integration Tab
        <div className="space-y-6">
          <div className="card">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
                <Server className="w-5 h-5 text-accent-blue" />
                Jenkins Servers
              </h2>
              <button className="btn-primary text-sm" disabled>
                <Server className="w-4 h-4" />
                Connect Server
              </button>
            </div>

            {jenkinsServers.length === 0 ? (
              <div className="text-center py-8 text-foreground-secondary">
                <Server className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p>No Jenkins servers connected</p>
                <p className="text-sm mt-1">Connect a Jenkins server to trigger jobs and view build status</p>
              </div>
            ) : (
              <div className="space-y-3">
                {jenkinsServers.map((server) => (
                  <div key={server.id} className="p-4 bg-background-tertiary rounded-lg flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className={clsx('p-2 rounded-lg', server.connected ? 'bg-accent-green/10' : 'bg-severity-critical/10')}>
                        <Server className={clsx('w-5 h-5', server.connected ? 'text-accent-green' : 'text-severity-critical')} />
                      </div>
                      <div>
                        <p className="font-medium text-foreground">{server.name}</p>
                        <p className="text-sm text-foreground-secondary font-mono">{server.url}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={clsx('badge', server.connected ? 'badge-success' : 'badge-critical')}>
                        {server.connected ? 'Connected' : 'Disconnected'}
                      </span>
                      <button className="btn-secondary text-sm" onClick={() => jenkinsApi.servers.test(server.id)}>
                        <RefreshCw className="w-3.5 h-3.5" />
                        Test
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {selectedServer && (
            <div className="card">
              <h3 className="font-medium text-foreground mb-4">Jobs</h3>
              <div className="text-foreground-secondary text-sm">Connect a Jenkins server to list jobs</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}