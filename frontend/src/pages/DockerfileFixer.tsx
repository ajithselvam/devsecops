import React, { useState, useCallback, useRef } from 'react';
import {
  FileText,
  Upload,
  Download,
  Copy,
  RotateCcw,
  Sparkles,
  Shield,
  CheckCircle,
  Info,
  HelpCircle,
  ChevronLeft,
  ChevronRight,
  Search,
  Filter,
  Settings
} from 'lucide-react';
import { dockerfileApi } from '../services/api';
import { DockerfileAnalysis, Severity, Finding } from '@devsecops/shared/types';
import { CodeEditor } from '../components/CodeEditor';
import { DiffViewer } from '../components/DiffViewer';
import { FindingList } from '../components/FindingCard';
import { toast } from 'react-hot-toast';
import { clsx } from 'clsx';

const DEFAULT_DOCKERFILE = `# Example vulnerable Dockerfile
FROM ubuntu:latest

# Running as root (bad practice)
USER root

# Install packages without pinning versions
RUN apt-get update && apt-get install -y \\
    nginx \\
    curl \\
    python3 \\
    python3-pip

# Copy application
COPY . /app
WORKDIR /app

# Install Python dependencies without pinning
RUN pip install -r requirements.txt

# Expose port
EXPOSE 80

# No health check
CMD ["nginx", "-g", "daemon off;"]`;

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

export function DockerfileFixer() {
  const [dockerfile, setDockerfile] = useState(DEFAULT_DOCKERFILE);
  const [analysis, setAnalysis] = useState<DockerfileAnalysis | null>(null);
  const [fixedDockerfile, setFixedDockerfile] = useState('');
  const [loading, setLoading] = useState(false);
  const [fixing, setFixing] = useState(false);
  const [viewMode, setViewMode] = useState<'editor' | 'diff' | 'side-by-side'>('editor');
  const [filterSeverity, setFilterSeverity] = useState<Severity[]>(['critical', 'high', 'medium', 'low', 'info']);
  const [filterType, setFilterType] = useState<string[]>([]);
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());
  const [showOnlyFixable, setShowOnlyFixable] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileUpload = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    if (!file.name.match(/^(Dockerfile|\.dockerfile$)/i) && !file.name.endsWith('.dockerfile')) {
      toast('File does not appear to be a Dockerfile', { icon: '⚠️' });
    }

    const reader = new FileReader();
    reader.onload = (e) => {
      setDockerfile(e.target?.result as string);
      setAnalysis(null);
      setFixedDockerfile('');
      setViewMode('editor');
      toast.success('Dockerfile loaded');
    };
    reader.readAsText(file);
    event.target.value = '';
  }, []);

  const handleAnalyze = async () => {
    if (!dockerfile.trim()) {
      toast.error('Please provide a Dockerfile');
      return;
    }

    setLoading(true);
    try {
      const response = await dockerfileApi.analyze(dockerfile);
      if (response.data.success) {
        setAnalysis(response.data.data);
        toast.success(`Analysis complete: ${response.data.data.issues.length} issues found`);
      } else {
        toast.error(response.data.error?.message || 'Analysis failed');
      }
    } catch (err) {
      toast.error('Failed to analyze Dockerfile');
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
      const response = await dockerfileApi.fix(dockerfile, analysis.issues);
      if (response.data.success) {
        setFixedDockerfile(response.data.data.fixedDockerfile);
        setAnalysis(prev => prev ? {
          ...prev,
          fixedDockerfile: response.data.data.fixedDockerfile,
          changes: response.data.data.changes,
          securityImprovements: response.data.data.securityImprovements,
          explanation: response.data.data.explanation
        } : null);
        setViewMode('side-by-side');
        toast.success('Dockerfile fixed successfully!');
      } else {
        toast.error(response.data.error?.message || 'Fix failed');
      }
    } catch (err) {
      toast.error('Failed to fix Dockerfile');
      console.error(err);
    } finally {
      setFixing(false);
    }
  };

  const handleApplyFixed = () => {
    if (fixedDockerfile) {
      setDockerfile(fixedDockerfile);
      setViewMode('editor');
      toast.success('Fixed version applied to editor');
    }
  };

  const handleReset = () => {
    setDockerfile(DEFAULT_DOCKERFILE);
    setAnalysis(null);
    setFixedDockerfile('');
    setViewMode('editor');
    toast.success('Reset to default');
  };

  const handleDownload = () => {
    const content = viewMode === 'editor' ? dockerfile : fixedDockerfile || dockerfile;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'Dockerfile.fixed';
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Downloaded');
  };

  const handleCopy = () => {
    const content = viewMode === 'editor' ? dockerfile : fixedDockerfile || dockerfile;
    navigator.clipboard.writeText(content);
    toast.success('Copied to clipboard');
  };

  const filteredIssues = analysis?.issues.filter(issue => {
    if (!filterSeverity.includes(issue.severity)) return false;
    if (filterType.length > 0 && !filterType.includes(issue.type)) return false;
    if (showOnlyFixable && !issue.fixable) return false;
    return true;
  }) || [];

  const sortedIssues = [...filteredIssues].sort((a, b) =>
    SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]
  );

  const issueTypes = [...new Set(analysis?.issues.map(i => i.type) || [])];

  const severityCounts = analysis?.issues.reduce((acc, issue) => {
    acc[issue.severity] = (acc[issue.severity] || 0) + 1;
    return acc;
  }, {} as Record<Severity, number>) || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  const toggleExpand = (findingId: string) => {
    setExpandedFindings(prev => {
      const next = new Set(prev);
      if (next.has(findingId)) next.delete(findingId);
      else next.add(findingId);
      return next;
    });
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Dockerfile AI Fixer</h1>
          <p className="text-foreground-secondary mt-1">
            Analyze, secure, and optimize your Dockerfiles with AI-powered fixes
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
            accept=".dockerfile,Dockerfile,.txt"
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

      {/* Toolbar */}
      <div className="card p-4">
        <div className="flex flex-wrap items-center gap-4">
          {/* View Mode Tabs */}
          <div className="tabs">
            <button
              className={clsx('tab', viewMode === 'editor' && 'tab-active')}
              onClick={() => setViewMode('editor')}
            >
              <FileText className="w-4 h-4" />
              Editor
            </button>
            {analysis && (
              <>
                <button
                  className={clsx('tab', viewMode === 'side-by-side' && 'tab-active')}
                  onClick={() => setViewMode('side-by-side')}
                >
                  <ChevronLeft className="w-4 h-4" />
                  <ChevronRight className="w-4 h-4" />
                  Diff
                </button>
                <button
                  className={clsx('tab', viewMode === 'diff' && 'tab-active')}
                  onClick={() => setViewMode('diff')}
                >
                  <Search className="w-4 h-4" />
                  Findings
                </button>
              </>
            )}
          </div>

          <div className="flex-1" />

          {/* Filters */}
          {analysis && (
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <Filter className="w-4 h-4 text-foreground-muted" />
                <select
                  className="input py-1.5 px-3 text-sm w-auto"
                  multiple
                  value={filterSeverity}
                  onChange={(e) => {
                    const selected = Array.from(e.target.selectedOptions).map(o => o.value as Severity);
                    setFilterSeverity(selected);
                  }}
                >
                  {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map(s => (
                    <option key={s} value={s} className="capitalize">
                      {s} ({severityCounts[s] || 0})
                    </option>
                  ))}
                </select>
              </div>

              {issueTypes.length > 0 && (
                <div className="flex items-center gap-2">
                  <Settings className="w-4 h-4 text-foreground-muted" />
                  <select
                    className="input py-1.5 px-3 text-sm w-auto"
                    multiple
                    value={filterType}
                    onChange={(e) => {
                      const selected = Array.from(e.target.selectedOptions).map(o => o.value);
                      setFilterType(selected);
                    }}
                  >
                    {issueTypes.map(t => (
                      <option key={t} value={t} className="capitalize">
                        {t.replace('_', ' ')}
                      </option>
                    ))}
                  </select>
                </div>
              )}

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

          {/* Action Buttons */}
          <div className="flex items-center gap-2">
            <button
              className="btn-primary"
              onClick={handleAnalyze}
              disabled={loading || !dockerfile.trim()}
            >
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

            {analysis && !fixedDockerfile && (
              <button
                className="btn-primary"
                onClick={handleFix}
                disabled={fixing}
              >
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

            {fixedDockerfile && viewMode !== 'editor' && (
              <button className="btn-secondary" onClick={handleApplyFixed}>
                <CheckCircle className="w-4 h-4" />
                Apply Fix
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Main Content */}
      {viewMode === 'editor' && (
        <div className="card p-0 overflow-hidden">
          <CodeEditor
            value={dockerfile}
            onChange={(value: string | undefined) => setDockerfile(value || '')}
            language="dockerfile"
            fileName="Dockerfile"
            maxHeight={500}
            placeholder="Paste or write your Dockerfile here..."
          />
        </div>
      )}

      {viewMode === 'side-by-side' && fixedDockerfile && analysis && (
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
              {analysis.securityImprovements && analysis.securityImprovements.length > 0 && (
                <div className="mt-3">
                  <p className="text-sm font-medium text-foreground mb-2">Security Improvements:</p>
                  <ul className="list-disc list-inside text-sm text-foreground-secondary space-y-1">
                    {analysis.securityImprovements.map((imp, i) => (
                      <li key={i} className="flex items-center gap-2">
                        <CheckCircle className="w-4 h-4 text-accent-green flex-shrink-0" />
                        {imp}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
          <DiffViewer
            original={dockerfile}
            fixed={fixedDockerfile}
            changes={analysis.changes || []}
            onApplyFixed={handleApplyFixed}
            onReset={handleReset}
          />
        </div>
      )}

      {viewMode === 'diff' && analysis && (
        <div className="card p-0 overflow-hidden">
          <FindingList
            findings={sortedIssues.map(f => ({
              id: f.id as Finding['id'],
              scanId: 'dockerfile' as Finding['scanId'],
              type: f.type as Finding['type'],
              severity: f.severity,
              title: f.message,
              description: f.suggestion || f.message,
              file: 'Dockerfile',
              line: f.line,
              ruleId: f.rule,
              fixable: f.fixable,
              remediation: f.fixable ? {
                available: true,
                type: 'patch' as const,
                description: f.suggestion || 'AI will generate a fix',
                steps: ['Run AI Fix to generate corrected Dockerfile'],
                confidence: 85,
                fixedContent: fixedDockerfile || undefined
              } : undefined,
              status: 'open' as const,
              createdAt: new Date().toISOString() as Finding['createdAt']
            }))}
            expandedIds={expandedFindings}
            onToggleExpand={(finding: any) => toggleExpand(finding.id)}
            showActions={false}
            emptyMessage="No issues found matching current filters"
          />
        </div>
      )}

      {/* Summary Stats */}
      {analysis && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map(sev => (
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

      {/* Help Section */}
      <div className="card">
        <h3 className="font-semibold text-foreground mb-4 flex items-center gap-2">
          <HelpCircle className="w-5 h-5 text-accent-blue" />
          What gets checked
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-sm text-foreground-secondary">
          {[
            'Syntax errors & invalid instructions',
            'Running as root user',
            'Large/unoptimized base images',
            'Missing health checks',
            'Missing dependency pinning',
            'Secrets in Dockerfile',
            'Package manager issues',
            'Cache inefficiencies',
            'Missing security labels',
            'Insecure permissions',
            'Outdated package versions',
            'Unnecessary packages'
          ].map((item, i) => (
            <div key={i} className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-accent-green flex-shrink-0" />
              {item}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}