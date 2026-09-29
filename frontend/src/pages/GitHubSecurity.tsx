import { useEffect, useState } from 'react';
import {
  Github,
  Shield,
  AlertTriangle,
  Key,
  Sparkles,
  GitBranch,
  Lock,
  Package,
  Code2,
  Zap,
  GitPullRequest,
  ChevronDown
} from 'lucide-react';
import { githubApi } from '../services/api';
import { Finding, Severity } from '@devsecops/shared/types';
import { FindingList } from '../components/FindingCard';
import { CodeEditor } from '../components/CodeEditor';
import { toast } from 'react-hot-toast';
import { clsx } from 'clsx';

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

export function GitHubSecurity() {
  const [connected, setConnected] = useState(false);
  const [token, setToken] = useState('');
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('main');
  const [scanTypes, setScanTypes] = useState<string[]>(['vulnerabilities', 'secrets', 'dependencies', 'code']);
  const [scanning, setScanning] = useState(false);
  const [scanStatus, setScanStatus] = useState('');
  const [progress, setProgress] = useState(0);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [summary, setSummary] = useState<any>(null);
  const [filterSeverity, setFilterSeverity] = useState<Severity[]>(['critical', 'high', 'medium', 'low', 'info']);
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [fixResult, setFixResult] = useState<any>(null);
  const [showTokenModal, setShowTokenModal] = useState(false);
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);

  useEffect(() => {
    githubApi.status()
      .then((res) => {
        if (res.data.success) setConnected(!!res.data.data.connected);
      })
      .catch(() => {});
  }, []);

  const apiError = (err: any, fallback: string) =>
    err?.response?.data?.error?.message || fallback;

  const handleConnect = async () => {
    if (!token.trim()) {
      toast.error('Please enter a GitHub token');
      return;
    }
    try {
      const response = await githubApi.connect(token.trim());
      if (response.data.success) {
        setConnected(true);
        setToken('');
        setShowTokenModal(false);
        toast.success('GitHub connected successfully');
      } else {
        toast.error(response.data.error?.message || 'Connection failed');
      }
    } catch (err) {
      toast.error(apiError(err, 'Failed to connect GitHub'));
      console.error(err);
    }
  };

  const handleScan = async () => {
    if (!repoUrl.trim()) {
      toast.error('Please enter a repository URL');
      return;
    }
    setScanning(true);
    setFindings([]);
    setSummary(null);
    setCurrentScanId(null);
    try {
      const response = await githubApi.scan(repoUrl.trim(), branch, scanTypes);
      if (response.data.success) {
        const scanId = response.data.data.scanId;
        setCurrentScanId(scanId);
        setScanStatus('running');
        toast.success('Scan started. This may take a few minutes.');

        let attempts = 0;
        const poll = setInterval(async () => {
          attempts += 1;
          if (attempts > 80) {
            clearInterval(poll);
            toast.error('Scan timed out. Check Scan History or try again.');
            setScanning(false);
            return;
          }
          try {
            const statusRes = await githubApi.scanStatus(scanId);
            if (statusRes.data.success) {
              const status = statusRes.data.data.status;
              setScanStatus(status);
              setProgress(statusRes.data.data.progress || 0);

              if (status === 'completed') {
                clearInterval(poll);
                const resultsRes = await githubApi.scanResults(scanId);
                if (resultsRes.data.success) {
                  const data = resultsRes.data.data;
                  const allFindings = [
                    ...(data.vulnerabilities || []).map((v: any) => ({
                      id: v.id,
                      scanId: scanId,
                      type: 'vulnerability' as const,
                      severity: v.severity,
                      title: `${v.package}: ${v.cve || v.id}`,
                      description: v.description,
                      package: v.package,
                      installedVersion: v.installedVersion,
                      fixedVersion: v.fixedVersion,
                      cve: v.cve || v.id,
                      fixable: v.fixAvailable,
                      remediation: v.fixAvailable ? {
                        available: true,
                        type: 'upgrade' as const,
                        description: `Upgrade ${v.package} to ${v.fixedVersion || 'latest'}`,
                        steps: [`Update ${v.package} to ${v.fixedVersion || 'latest'}`],
                        confidence: 90
                      } : undefined,
                      status: 'open' as const,
                      createdAt: new Date().toISOString()
                    })),
                    ...(data.secrets || []).map((s: any) => ({
                      id: s.id,
                      scanId: scanId,
                      type: 'secret' as const,
                      severity: s.severity,
                      title: `Secret detected: ${s.type}`,
                      description: s.message,
                      file: s.file,
                      line: s.line,
                      ruleId: s.rule,
                      fixable: false,
                      status: 'open' as const,
                      createdAt: new Date().toISOString()
                    })),
                    ...(data.codeIssues || []).map((c: any) => ({
                      id: c.id,
                      scanId: scanId,
                      type: 'security_issue' as const,
                      severity: c.severity,
                      title: c.message,
                      description: c.message,
                      file: c.file,
                      line: c.line,
                      code: c.code,
                      ruleId: c.ruleId,
                      fixable: c.fixable,
                      remediation: c.fixable ? {
                        available: true,
                        type: 'patch' as const,
                        description: c.suggestion || 'AI will generate a fix',
                        steps: ['Run AI Fix to generate patch'],
                        confidence: 80
                      } : undefined,
                      status: 'open' as const,
                      createdAt: new Date().toISOString()
                    }))
                  ];
                  setFindings(allFindings);
                  setSummary(data.summary || {});
                  toast.success('Scan complete!');
                }
                setScanning(false);
              } else if (status === 'failed') {
                clearInterval(poll);
                toast.error('Scan failed');
                setScanning(false);
              }
            }
          } catch (err) {
            console.error(err);
          }
        }, 3000);
      } else {
        toast.error(response.data.error?.message || 'Scan failed');
        setScanning(false);
      }
    } catch (err) {
      toast.error(apiError(err, 'Failed to start scan'));
      console.error(err);
      setScanning(false);
    }
  };

  const handleFix = async (finding: Finding) => {
    setSelectedFinding(finding);
    try {
      const response = await githubApi.fix(
        finding.id,
        repoUrl || 'repo',
        branch,
        finding.type === 'vulnerability' ? 'upgrade' : 'patch',
        finding.scanId || currentScanId || undefined
      );
      if (response.data.success) {
        setFixResult(response.data.data);
        toast.success('Fix generated successfully!');
      } else {
        toast.error(response.data.error?.message || 'Fix failed');
      }
    } catch (err) {
      toast.error(apiError(err, 'Failed to generate fix'));
      console.error(err);
    }
  };

  const handleCreatePR = async () => {
    try {
      const response = await githubApi.createPR({
        repoId: repoUrl,
        branch: `fix/${selectedFinding?.id?.slice(0, 8) || Date.now()}`,
        title: `Fix: ${selectedFinding?.title}`,
        body: fixResult?.explanation || '',
        changes: fixResult?.changes || []
      });
      if (response.data.success) {
        toast.success(response.data.data.prUrl ? `Pull request created: ${response.data.data.prUrl}` : 'Pull request created!');
      } else {
        toast.error(response.data.error?.message || 'PR creation failed');
      }
    } catch (err) {
      toast.error(apiError(err, 'Failed to create PR'));
      console.error(err);
    }
  };

  const toggleExpand = (finding: Finding) => {
    setExpandedFindings(prev => {
      const next = new Set(prev);
      if (next.has(finding.id)) next.delete(finding.id);
      else next.add(finding.id);
      return next;
    });
  };

  const filteredFindings = findings.filter(f => filterSeverity.includes(f.severity));
  const sortedFindings = [...filteredFindings].sort((a, b) =>
    SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]
  );

  const severityCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {} as Record<Severity, number>);

  const securityScore = summary?.securityScore || 0;
  const depsScore = summary?.dependenciesScore || 0;
  const secretsScore = summary?.secretsScore || 0;
  const codeScore = summary?.codeScore || 0;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground">GitHub Repository Security</h1>
          <p className="text-foreground-secondary mt-1">
            Clone, scan, and secure your repositories with AI-powered fixes
          </p>
        </div>
        <button
          className="btn-secondary"
          onClick={async () => {
            if (connected) {
              try {
                await githubApi.disconnect();
              } catch {
                // still disconnect locally
              }
              setConnected(false);
              toast.success('GitHub disconnected');
            } else {
              setShowTokenModal(true);
            }
          }}
        >
          <Key className="w-4 h-4" />
          {connected ? 'Disconnect' : 'Connect GitHub'}
        </button>
      </div>

      {/* Token Modal */}
      {showTokenModal && (
        <div className="modal-overlay" onClick={() => setShowTokenModal(false)}>
          <div className="modal-content w-full max-w-md p-6" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-foreground mb-4 flex items-center gap-2">
              <Key className="w-5 h-5" />
              Connect GitHub
            </h2>
            <div className="space-y-4">
              <div>
                <label className="label">Personal Access Token</label>
                <input
                  type="password"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  placeholder="ghp_..."
                  className="input"
                />
                <p className="text-xs text-foreground-muted mt-1">
                  Token is encrypted and stored server-side. Never exposed in frontend.
                </p>
              </div>
              <div className="flex gap-2">
                <button className="btn-secondary flex-1" onClick={() => setShowTokenModal(false)}>
                  Cancel
                </button>
                <button className="btn-primary flex-1" onClick={handleConnect}>
                  Connect
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Input Section */}
      <div className="card">
        <div className="flex flex-col lg:flex-row gap-4">
          <div className="flex-1">
            <label className="label">Repository URL</label>
            <div className="relative">
              <Github className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-foreground-muted" />
              <input
                type="text"
                value={repoUrl}
                onChange={(e) => setRepoUrl(e.target.value)}
                placeholder="https://github.com/user/repo"
                className="input pl-10"
                disabled={scanning}
              />
            </div>
          </div>
          <div className="w-full lg:w-40">
            <label className="label">Branch</label>
            <input
              type="text"
              value={branch}
              onChange={(e) => setBranch(e.target.value)}
              className="input"
              disabled={scanning}
            />
          </div>
        </div>

        <div className="mt-4">
          <p className="label">Scan Types</p>
          <div className="flex flex-wrap gap-2">
            {[
              { key: 'vulnerabilities', label: 'Vulnerabilities', icon: AlertTriangle },
              { key: 'secrets', label: 'Secrets', icon: Lock },
              { key: 'dependencies', label: 'Dependencies', icon: Package },
              { key: 'code', label: 'Code', icon: Code2 }
            ].map(({ key, label, icon: Icon }) => (
              <label
                key={key}
                className={clsx(
                  'flex items-center gap-2 px-3 py-2 rounded-lg text-sm cursor-pointer transition-colors',
                  scanTypes.includes(key)
                    ? 'bg-accent-blue/20 text-accent-blue border border-accent-blue/30'
                    : 'bg-background-tertiary text-foreground-secondary'
                )}
              >
                <input
                  type="checkbox"
                  checked={scanTypes.includes(key)}
                  onChange={(e) => {
                    if (e.target.checked) setScanTypes([...scanTypes, key]);
                    else setScanTypes(scanTypes.filter(t => t !== key));
                  }}
                  className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue"
                />
                <Icon className="w-4 h-4" />
                {label}
              </label>
            ))}
          </div>
        </div>

        <div className="mt-4 flex items-center gap-2">
          <button className="btn-primary" onClick={handleScan} disabled={scanning || !repoUrl.trim()}>
            {scanning ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <Shield className="w-4 h-4" />
                Scan Repository
              </>
            )}
          </button>
          {scanning && (
            <div className="flex-1">
              <div className="progress-bar">
                <div className="progress-fill bg-accent-blue" style={{ width: `${progress}%` }} />
              </div>
              <p className="text-xs text-foreground-secondary mt-1">
                {scanStatus} - {progress}%
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Security Score */}
      {summary && (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: 'Security', score: securityScore, icon: Shield },
            { label: 'Dependencies', score: depsScore, icon: Package },
            { label: 'Secrets', score: secretsScore, icon: Lock },
            { label: 'Code Quality', score: codeScore, icon: Code2 }
          ].map(({ label, score, icon: Icon }) => (
            <div key={label} className="card">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-foreground-secondary">{label}</span>
                <Icon className="w-5 h-5 text-accent-blue" />
              </div>
              <div className="flex items-baseline gap-1">
                <span className="text-3xl font-bold text-foreground">{score}</span>
                <span className="text-sm text-foreground-muted">/100</span>
              </div>
              <div className="mt-2">
                <div className="progress-bar">
                  <div
                    className="progress-fill"
                    style={{
                      width: `${score}%`,
                      backgroundColor: score >= 80 ? 'var(--color-accent-green)' : score >= 60 ? 'var(--color-severity-medium)' : 'var(--color-severity-critical)'
                    }}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Severity Summary */}
      {findings.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
          {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map(sev => (
            <button
              key={sev}
              className={clsx(
                'card p-3 text-center transition-all',
                filterSeverity.includes(sev) ? `border-l-4 border-severity-${sev}` : 'opacity-50'
              )}
              onClick={() => {
                if (filterSeverity.includes(sev)) setFilterSeverity(filterSeverity.filter(s => s !== sev));
                else setFilterSeverity([...filterSeverity, sev]);
              }}
            >
              <p className="text-2xl font-bold" style={{ color: `var(--color-severity-${sev})` }}>
                {severityCounts[sev] || 0}
              </p>
              <p className="text-xs text-foreground-secondary capitalize">{sev}</p>
            </button>
          ))}
          <div className="card p-3 text-center">
            <p className="text-2xl font-bold text-foreground">{findings.length}</p>
            <p className="text-xs text-foreground-secondary">Total</p>
          </div>
        </div>
      )}

      {/* Findings */}
      {findings.length > 0 && (
        <div className="card p-0 overflow-hidden">
          <FindingList
            findings={sortedFindings}
            expandedIds={expandedFindings}
            onToggleExpand={toggleExpand}
            onFix={handleFix}
            onIgnore={(f) => {
              setFindings(prev => prev.filter(x => x.id !== f.id));
              toast.success('Finding ignored');
            }}
            emptyMessage="No findings for selected severity"
          />
        </div>
      )}

      {/* Fix Result Modal */}
      {fixResult && selectedFinding && (
        <div className="modal-overlay" onClick={() => setFixResult(null)}>
          <div className="modal-content w-full max-w-4xl p-6" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-accent-purple" />
                AI Fix: {selectedFinding.title}
              </h2>
              <button className="btn-icon" onClick={() => setFixResult(null)}>
                <ChevronDown className="w-5 h-5" />
              </button>
            </div>

            {fixResult.explanation && (
              <div className="mb-4 p-3 bg-background-tertiary rounded-lg">
                <p className="text-sm text-foreground-secondary">{fixResult.explanation}</p>
              </div>
            )}

            {fixResult.patch && (
              <div className="mb-4">
                <p className="font-medium text-foreground mb-2">Patch</p>
                <CodeEditor
                  value={fixResult.patch}
                  onChange={() => {}}
                  language="json"
                  maxHeight={300}
                  readOnly
                />
              </div>
            )}

            <div className="flex gap-2">
              <button className="btn-secondary" onClick={() => setFixResult(null)}>
                Cancel
              </button>
              <button className="btn-primary" onClick={handleCreatePR}>
                <GitPullRequest className="w-4 h-4" />
                Create PR
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Help Section */}
      <div className="card">
        <h3 className="font-semibold text-foreground mb-4 flex items-center gap-2">
          <Zap className="w-5 h-5 text-accent-yellow" />
          How it works
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm text-foreground-secondary">
          <div className="p-3 bg-background-tertiary rounded-lg">
            <GitBranch className="w-5 h-5 text-accent-blue mb-2" />
            <p className="font-medium text-foreground mb-1">1. Clone</p>
            <p>Securely clone the repository</p>
          </div>
          <div className="p-3 bg-background-tertiary rounded-lg">
            <Package className="w-5 h-5 text-accent-green mb-2" />
            <p className="font-medium text-foreground mb-1">2. SBOM</p>
            <p>Generate software bill of materials with Syft</p>
          </div>
          <div className="p-3 bg-background-tertiary rounded-lg">
            <Shield className="w-5 h-5 text-accent-purple mb-2" />
            <p className="font-medium text-foreground mb-1">3. Scan</p>
            <p>Grype, Trivy, Semgrep, Gitleaks</p>
          </div>
          <div className="p-3 bg-background-tertiary rounded-lg">
            <GitPullRequest className="w-5 h-5 text-accent-yellow mb-2" />
            <p className="font-medium text-foreground mb-1">4. Fix</p>
            <p>AI generates safe patches as PRs</p>
          </div>
        </div>
      </div>
    </div>
  );
}