import React, { useState, useCallback, useEffect, useRef } from 'react';
import {
  Package,
  Radar,
  Upload,
  Download,
  Copy,
  Search,
  Sparkles,
  Shield,
  AlertTriangle,
  CheckCircle,
  Clock,
  GitBranch,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Link2,
  FileText,
  Zap,
  Wrench,
  Terminal,
  ArrowRight
} from 'lucide-react';
import { dependenciesApi } from '../services/api';
import {
  DependencyScan,
  DependencyNode,
  DependencyRemediation,
  SBOMFormat
} from '@devsecops/shared/types';
import { toast } from 'react-hot-toast';
import { clsx } from 'clsx';
import { formatDistanceToNow } from 'date-fns';

const SEVERITY_ORDER: Record<string, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

const SEVERITY_COLORS: Record<string, { text: string; bg: string }> = {
  critical: { text: 'text-severity-critical', bg: 'bg-severity-critical/10' },
  high: { text: 'text-severity-high', bg: 'bg-severity-high/10' },
  medium: { text: 'text-severity-medium', bg: 'bg-severity-medium/10' },
  low: { text: 'text-severity-low', bg: 'bg-severity-low/10' },
  info: { text: 'text-severity-info', bg: 'bg-severity-info/10' }
};

export function DependencyRadar() {
  const [scans, setScans] = useState<DependencyScan[]>([]);
  const [currentScan, setCurrentScan] = useState<DependencyScan | null>(null);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [repoUrl, setRepoUrl] = useState('');
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<string[]>([]);
  const [filterSeverity, setFilterSeverity] = useState<string[]>([]);
  const [sortBy, setSortBy] = useState<'name' | 'severity' | 'version'>('name');
  const [expandedDeps, setExpandedDeps] = useState<Set<string>>(new Set());
  const [remediation, setRemediation] = useState<DependencyRemediation | null>(null);
  const [remediating, setRemediating] = useState(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'dependencies' | 'vulnerabilities' | 'sbom'>('overview');
  const [sbomFormat, setSbomFormat] = useState<SBOMFormat>('cyclonedx');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const loadScans = useCallback(async () => {
    setLoading(true);
    try {
      const response = await dependenciesApi.list();
      if (response.data.success) {
        setScans(response.data.data || []);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadScans();
  }, [loadScans]);

  const handleUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    setUploading(true);
    try {
      const response = await dependenciesApi.upload(file);
      if (response.data.success) {
        const scan = response.data.data;
        setScans(prev => [scan, ...prev]);
        setCurrentScan(scan);
        setActiveTab('overview');
        toast.success('Dependency scan complete!');
      } else {
        toast.error(response.data.error?.message || 'Upload failed');
      }
    } catch (err: any) {
      toast.error(err?.response?.data?.error?.message || 'Upload failed');
      console.error(err);
    } finally {
      setUploading(false);
      event.target.value = '';
    }
  };

  const handleScanRepo = async () => {
    if (!repoUrl.trim()) {
      toast.error('Please enter a repository URL');
      return;
    }
    setScanning(true);
    setProgress(8);
    const tick = setInterval(() => {
      setProgress(p => (p < 90 ? p + 7 : p));
    }, 800);
    try {
      const response = await dependenciesApi.scanRepo(repoUrl.trim(), 'main');
      if (response.data.success) {
        const scan = response.data.data;
        setScans(prev => [scan, ...prev]);
        setCurrentScan(scan);
        setActiveTab('overview');
        setProgress(100);
        toast.success('Repository scan complete!');
      } else {
        toast.error(response.data.error?.message || 'Scan failed');
      }
    } catch (err: any) {
      toast.error(err?.response?.data?.error?.message || 'Scan failed');
      console.error(err);
    } finally {
      clearInterval(tick);
      setScanning(false);
    }
  };

  const handleSelectScan = async (id: string) => {
    setLoading(true);
    try {
      const response = await dependenciesApi.get(id);
      if (response.data.success) {
        setCurrentScan(response.data.data);
        setActiveTab('overview');
        setRemediation(null);
      }
    } catch (err) {
      toast.error('Failed to load scan');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleRemediate = async (dependency: DependencyNode) => {
    if (!currentScan) return;
    setRemediating(true);
    try {
      const response = await dependenciesApi.remediate(currentScan.id, dependency.name, dependency.version);
      if (response.data.success) {
        setRemediation(response.data.data);
        toast.success('AI remediation generated!');
      } else {
        toast.error(response.data.error?.message || 'Remediation failed');
      }
    } catch (err) {
      toast.error('Remediation failed');
      console.error(err);
    } finally {
      setRemediating(false);
    }
  };

  const handleExportSBOM = async () => {
    if (!currentScan) return;
    try {
      const response = await dependenciesApi.exportSBOM(currentScan.id, sbomFormat);
      if (response.data.success) {
        const blob = new Blob([JSON.stringify(response.data.data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `sbom-${currentScan.id}.${sbomFormat === 'cyclonedx' ? 'json' : 'spdx.json'}`;
        a.click();
        URL.revokeObjectURL(url);
        toast.success('SBOM downloaded');
      } else {
        toast.error(response.data.error?.message || 'Export failed');
      }
    } catch (err) {
      toast.error('Export failed');
      console.error(err);
    }
  };

  const filteredDependencies = currentScan
    ? currentScan.dependencies.filter(dep => {
        if (searchQuery && !dep.name.toLowerCase().includes(searchQuery.toLowerCase()) &&
            !dep.version.toLowerCase().includes(searchQuery.toLowerCase())) {
          return false;
        }
        if (filterType.length > 0 && !filterType.includes(dep.type)) {
          return false;
        }
        if (filterSeverity.length > 0 && !dep.vulnerabilities.some(v => filterSeverity.includes(v.severity))) {
          return false;
        }
        return true;
      })
    : [];

  const sortedDependencies = [...filteredDependencies].sort((a, b) => {
    if (sortBy === 'name') return a.name.localeCompare(b.name);
    if (sortBy === 'version') return a.version.localeCompare(b.version);
    if (sortBy === 'severity') {
      const aScore = a.vulnerabilities.length > 0 ? Math.max(...a.vulnerabilities.map(v => SEVERITY_ORDER[v.severity])) : 0;
      const bScore = b.vulnerabilities.length > 0 ? Math.max(...b.vulnerabilities.map(v => SEVERITY_ORDER[v.severity])) : 0;
      return bScore - aScore;
    }
    return 0;
  });

  const getVulnCounts = (deps: DependencyNode[]) => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    deps.forEach(dep => dep.vulnerabilities.forEach(v => {
      if (counts[v.severity] !== undefined) counts[v.severity]++;
    }));
    return counts;
  };

  const toggleExpand = (id: string) => {
    setExpandedDeps(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Dependency Radar</h1>
          <p className="text-foreground-secondary mt-1">
            SBOM generation, vulnerability scanning, and AI-powered remediation
          </p>
        </div>
      </div>

      {/* Input Section */}
      <div className="card">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          <div>
            <label className="label">Scan Repository (GitHub URL)</label>
            <div className="flex gap-2">
              <div className="flex-1 relative">
                <GitBranch className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-foreground-muted" />
                <input
                  type="text"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  placeholder="https://github.com/user/repo"
                  className="input pl-10"
                  disabled={scanning}
                />
              </div>
              <button className="btn-primary" onClick={handleScanRepo} disabled={scanning || !repoUrl.trim()}>
                {scanning ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Radar className="w-4 h-4" />
                    Scan
                  </>
                )}
              </button>
            </div>
            {scanning && (
              <div className="mt-2">
                <div className="progress-bar">
                  <div className="progress-fill bg-accent-blue" style={{ width: `${progress}%` }} />
                </div>
                <p className="text-xs text-foreground-secondary mt-1">{progress}% - Cloning & analyzing dependencies</p>
              </div>
            )}
          </div>

          <div>
            <label className="label">Or Upload Manifest</label>
            <div className="flex gap-2">
              <button
                className="btn-secondary flex-1"
                onClick={() => fileInputRef.current?.click()}
                disabled={uploading}
              >
                {uploading ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Upload className="w-4 h-4" />
                    Upload package.json / pom.xml
                  </>
                )}
              </button>
              <input
                ref={fileInputRef}
                type="file"
                accept=".json,.xml,.txt,.lock,.yml,.yaml"
                onChange={handleUpload}
                className="hidden"
              />
            </div>
            <p className="text-xs text-foreground-muted mt-1">
              Supports: package.json, package-lock.json, pom.xml, requirements.txt, go.mod, Cargo.toml
            </p>
          </div>
        </div>
      </div>

      {/* Scan History Sidebar */}
      {scans.length > 0 && (
        <div className="card">
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-medium text-foreground">Recent Scans</h3>
            <button className="btn-secondary text-sm" onClick={loadScans}>
              <RefreshCw className="w-3.5 h-3.5" />
              Refresh
            </button>
          </div>
          <div className="flex flex-wrap gap-2">
            {scans.slice(0, 8).map((scan) => (
              <button
                key={scan.id}
                className={clsx(
                  'px-3 py-2 rounded-lg text-sm transition-colors text-left',
                  currentScan?.id === scan.id
                    ? 'bg-accent-blue/20 text-accent-blue border border-accent-blue/30'
                    : 'bg-background-tertiary text-foreground-secondary hover:bg-background-elevated'
                )}
                onClick={() => handleSelectScan(scan.id)}
              >
                <div className="font-medium">{scan.name}</div>
                <div className="text-xs opacity-70">
                  {scan.dependencies.length} deps • {formatDistanceToNow(new Date(scan.createdAt), { addSuffix: true })}
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

      {loading && !currentScan && (
        <div className="flex items-center justify-center h-64">
          <div className="flex flex-col items-center gap-3">
            <div className="w-8 h-8 border-2 border-accent-blue/30 border-t-accent-blue rounded-full animate-spin" />
            <p className="text-foreground-secondary">Loading scan...</p>
          </div>
        </div>
      )}

      {currentScan && (
        <>
          {/* Tabs */}
          <div className="tabs">
            <button className={clsx('tab', activeTab === 'overview' && 'tab-active')} onClick={() => setActiveTab('overview')}>
              <Shield className="w-4 h-4" />
              Overview
            </button>
            <button className={clsx('tab', activeTab === 'dependencies' && 'tab-active')} onClick={() => setActiveTab('dependencies')}>
              <Package className="w-4 h-4" />
              Dependencies ({currentScan.dependencies.length})
            </button>
            <button className={clsx('tab', activeTab === 'vulnerabilities' && 'tab-active')} onClick={() => setActiveTab('vulnerabilities')}>
              <AlertTriangle className="w-4 h-4" />
              Vulnerabilities ({currentScan.dependencies.reduce((acc, d) => acc + d.vulnerabilities.length, 0)})
            </button>
            <button className={clsx('tab', activeTab === 'sbom' && 'tab-active')} onClick={() => setActiveTab('sbom')}>
              <FileText className="w-4 h-4" />
              SBOM
            </button>
          </div>

          {/* Overview Tab */}
          {activeTab === 'overview' && (
            <>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="card">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm text-foreground-secondary">Total Dependencies</span>
                    <Package className="w-5 h-5 text-accent-blue" />
                  </div>
                  <span className="text-3xl font-bold text-foreground">{currentScan.dependencies.length}</span>
                  <p className="text-xs text-foreground-muted mt-1">
                    {currentScan.dependencies.filter(d => d.type === 'direct').length} direct, {currentScan.dependencies.filter(d => d.type === 'transitive').length} transitive
                  </p>
                </div>
                <div className="card">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm text-foreground-secondary">Vulnerabilities</span>
                    <AlertTriangle className="w-5 h-5 text-severity-critical" />
                  </div>
                  <span className="text-3xl font-bold text-severity-critical">
                    {currentScan.dependencies.reduce((acc, d) => acc + d.vulnerabilities.length, 0)}
                  </span>
                  <p className="text-xs text-foreground-muted mt-1">
                    Across {currentScan.dependencies.filter(d => d.vulnerabilities.length > 0).length} packages
                  </p>
                </div>
                <div className="card">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm text-foreground-secondary">Health Score</span>
                    <Shield className="w-5 h-5 text-accent-green" />
                  </div>
                  <span className="text-3xl font-bold text-accent-green">{currentScan.healthScore ?? 0}/100</span>
                  <div className="mt-2">
                    <div className="progress-bar">
                      <div
                        className="progress-fill"
                        style={{
                          width: `${currentScan.healthScore ?? 0}%`,
                          backgroundColor: (currentScan.healthScore ?? 0) >= 80 ? 'var(--color-accent-green)' : (currentScan.healthScore ?? 0) >= 60 ? 'var(--color-severity-medium)' : 'var(--color-severity-critical)'
                        }}
                      />
                    </div>
                  </div>
                </div>
                <div className="card">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-sm text-foreground-secondary">Outdated</span>
                    <Clock className="w-5 h-5 text-accent-yellow" />
                  </div>
                  <span className="text-3xl font-bold text-accent-yellow">
                    {currentScan.dependencies.filter(d => d.latestVersion && d.latestVersion !== d.version).length}
                  </span>
                  <p className="text-xs text-foreground-muted mt-1">Updates available</p>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="card">
                  <h3 className="font-medium text-foreground mb-4">Severity Breakdown</h3>
                  <div className="space-y-3">
                    {(['critical', 'high', 'medium', 'low', 'info'] as const).map(sev => {
                      const count = getVulnCounts(currentScan.dependencies)[sev];
                      const total = Object.values(getVulnCounts(currentScan.dependencies)).reduce((a, b) => a + b, 0);
                      const percentage = total > 0 ? (count / total) * 100 : 0;
                      return (
                        <div key={sev} className="flex items-center gap-3">
                          <span className={clsx('w-16 text-sm capitalize', SEVERITY_COLORS[sev].text)}>{sev}</span>
                          <div className="flex-1 progress-bar">
                            <div
                              className="progress-fill"
                              style={{
                                width: `${percentage}%`,
                                backgroundColor: `var(--color-severity-${sev})`
                              }}
                            />
                          </div>
                          <span className="text-sm text-foreground font-mono w-8 text-right">{count}</span>
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div className="card">
                  <h3 className="font-medium text-foreground mb-4">Top Vulnerable Packages</h3>
                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {currentScan.dependencies
                      .filter(d => d.vulnerabilities.length > 0)
                      .sort((a, b) => b.vulnerabilities.length - a.vulnerabilities.length)
                      .slice(0, 6)
                      .map(dep => (
                        <div key={dep.name} className="flex items-center justify-between p-2 bg-background-tertiary rounded-lg">
                          <div className="min-w-0 flex-1">
                            <p className="font-mono text-sm text-foreground truncate">{dep.name}</p>
                            <p className="text-xs text-foreground-muted">v{dep.version}</p>
                          </div>
                          <div className="flex gap-1">
                            {dep.vulnerabilities.slice(0, 3).map((v, i) => (
                              <span
                                key={i}
                                className={clsx('badge', SEVERITY_COLORS[v.severity].bg, SEVERITY_COLORS[v.severity].text)}
                              >
                                {v.severity[0].toUpperCase()}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))}
                  </div>
                </div>
              </div>
            </>
          )}

          {/* Dependencies Tab */}
          {activeTab === 'dependencies' && (
            <>
              <div className="card">
                <div className="flex flex-col sm:flex-row sm:items-center gap-3 mb-4">
                  <div className="relative flex-1">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-foreground-muted" />
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Search dependencies..."
                      className="input pl-10"
                    />
                  </div>
                  <select
                    className="input w-auto py-2"
                    value={sortBy}
                    onChange={(e) => setSortBy(e.target.value as any)}
                  >
                    <option value="name">Sort: Name</option>
                    <option value="version">Sort: Version</option>
                    <option value="severity">Sort: Severity</option>
                  </select>
                </div>

                <div className="flex flex-wrap gap-2 mb-4">
                  {['direct', 'transitive'].map(type => (
                    <button
                      key={type}
                      className={clsx(
                        'px-3 py-1.5 rounded-lg text-sm transition-colors',
                        filterType.includes(type)
                          ? 'bg-accent-blue/20 text-accent-blue border border-accent-blue/30'
                          : 'bg-background-tertiary text-foreground-secondary'
                      )}
                      onClick={() => {
                        setFilterType(prev =>
                          prev.includes(type) ? prev.filter(t => t !== type) : [...prev, type]
                        );
                      }}
                    >
                      {type}
                    </button>
                  ))}
                  {(['critical', 'high', 'medium', 'low'] as const).map(sev => (
                    <button
                      key={sev}
                      className={clsx(
                        'px-3 py-1.5 rounded-lg text-sm transition-colors',
                        filterSeverity.includes(sev)
                          ? 'bg-accent-blue/20 text-accent-blue border border-accent-blue/30'
                          : 'bg-background-tertiary text-foreground-secondary'
                      )}
                      onClick={() => {
                        setFilterSeverity(prev =>
                          prev.includes(sev) ? prev.filter(s => s !== sev) : [...prev, sev]
                        );
                      }}
                    >
                      {sev}
                    </button>
                  ))}
                </div>

                <div className="space-y-2">
                  {sortedDependencies.map(dep => (
                    <div
                      key={`${dep.name}-${dep.version}`}
                      className={clsx(
                        'p-3 bg-background-tertiary rounded-lg transition-colors',
                        dep.vulnerabilities.length > 0 ? 'border-l-4 border-severity-high' : ''
                      )}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3 flex-1 min-w-0">
                          <Package className="w-5 h-5 text-accent-blue flex-shrink-0" />
                          <div className="min-w-0 flex-1">
                            <p className="font-mono text-sm text-foreground truncate">{dep.name}</p>
                            <div className="flex items-center gap-2 mt-0.5">
                              <span className="text-xs text-foreground-muted">v{dep.version}</span>
                              {dep.latestVersion && dep.latestVersion !== dep.version && (
                                <span className="text-xs text-accent-yellow flex items-center gap-1">
                                  <Clock className="w-3 h-3" />
                                  latest: {dep.latestVersion}
                                </span>
                              )}
                              <span className={clsx('badge text-xs', dep.type === 'direct' ? 'badge-info' : 'badge-ghost')}>
                                {dep.type}
                              </span>
                            </div>
                          </div>
                          {dep.vulnerabilities.length > 0 && (
                            <button
                              className="btn-icon"
                              onClick={() => toggleExpand(dep.name)}
                            >
                              {expandedDeps.has(dep.name) ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                            </button>
                          )}
                        </div>
                        <div className="flex items-center gap-2 ml-2">
                          {dep.vulnerabilities.length > 0 ? (
                            <span className={clsx('badge', SEVERITY_COLORS[dep.vulnerabilities[0].severity].bg, SEVERITY_COLORS[dep.vulnerabilities[0].severity].text)}>
                              {dep.vulnerabilities.length} vuln
                            </span>
                          ) : (
                            <span className="badge badge-success">Safe</span>
                          )}
                          {dep.vulnerabilities.length > 0 && (
                            <button
                              className="btn-secondary text-xs px-2 py-1"
                              onClick={() => handleRemediate(dep)}
                              disabled={remediating}
                            >
                              <Sparkles className="w-3 h-3" />
                              AI Fix
                            </button>
                          )}
                        </div>
                      </div>

                      {expandedDeps.has(dep.name) && dep.vulnerabilities.length > 0 && (
                        <div className="mt-3 pl-8 space-y-2">
                          {dep.vulnerabilities.map((vuln, i) => (
                            <div key={i} className={clsx('p-2 rounded-lg', SEVERITY_COLORS[vuln.severity].bg)}>
                              <div className="flex items-center justify-between">
                                <span className={clsx('text-sm font-medium', SEVERITY_COLORS[vuln.severity].text)}>
                                  {vuln.id}
                                </span>
                                <span className="text-xs text-foreground-muted">{vuln.severity}</span>
                              </div>
                              <p className="text-xs text-foreground-secondary mt-1">{vuln.title}</p>
                              {vuln.fixedVersion && (
                                <p className="text-xs text-accent-green mt-1 flex items-center gap-1">
                                  <CheckCircle className="w-3 h-3" />
                                  Fixed in: {vuln.fixedVersion}
                                </p>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </>
          )}

          {/* Vulnerabilities Tab */}
          {activeTab === 'vulnerabilities' && (
            <>
              <div className="card">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-medium text-foreground">All Vulnerabilities</h3>
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-foreground-muted" />
                    <input
                      type="text"
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      placeholder="Filter by CVE or package..."
                      className="input pl-9 py-1.5 text-sm w-64"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  {currentScan.dependencies
                    .flatMap(dep => dep.vulnerabilities.map(v => ({ ...v, package: dep.name, version: dep.version })))
                    .filter(v => !searchQuery || v.package.toLowerCase().includes(searchQuery.toLowerCase()) || v.id.toLowerCase().includes(searchQuery.toLowerCase()))
                    .sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity])
                    .map((vuln, i) => (
                      <div key={i} className={clsx('p-3 rounded-lg border-l-4', SEVERITY_COLORS[vuln.severity].bg, `border-severity-${vuln.severity}`)}>
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className={clsx('font-mono text-sm font-medium', SEVERITY_COLORS[vuln.severity].text)}>
                                {vuln.id}
                              </span>
                              <span className="badge badge-ghost">{vuln.severity}</span>
                              <span className={clsx('badge', SEVERITY_COLORS[vuln.severity].bg, SEVERITY_COLORS[vuln.severity].text)}>
                                CVSS {vuln.cvssScore}
                              </span>
                            </div>
                            <p className="text-sm text-foreground-secondary mt-1">{vuln.title}</p>
                            <div className="flex items-center gap-2 mt-2 text-xs text-foreground-muted">
                              <Package className="w-3 h-3" />
                              <span className="font-mono">{vuln.package}</span>
                              <span>v{vuln.version}</span>
                              {vuln.fixedVersion && (
                                <>
                                  <ArrowRight className="w-3 h-3" />
                                  <span className="text-accent-green">v{vuln.fixedVersion}</span>
                                </>
                              )}
                            </div>
                            <div className="flex flex-wrap gap-1 mt-2">
                              {vuln.references?.slice(0, 3).map((ref, j) => (
                                <a key={j} href={ref} target="_blank" rel="noopener noreferrer" className="badge badge-info text-xs">
                                  <Link2 className="w-2.5 h-2.5" />
                                  Ref
                                </a>
                              ))}
                            </div>
                          </div>
                          {vuln.fixedVersion && (
                            <button
                              className="btn-secondary text-xs px-2 py-1 whitespace-nowrap"
                              onClick={() => {
                                const dep = currentScan.dependencies.find(d => d.name === vuln.package);
                                if (dep) handleRemediate(dep);
                              }}
                              disabled={remediating}
                            >
                              <Sparkles className="w-3 h-3" />
                              AI Fix
                            </button>
                          )}
                        </div>
                      </div>
                    ))}
                </div>
              </div>
            </>
          )}

          {/* SBOM Tab */}
          {activeTab === 'sbom' && (
            <>
              <div className="card">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-medium text-foreground">Software Bill of Materials (SBOM)</h3>
                  <div className="flex gap-2">
                    <select
                      className="input py-1.5 px-3 text-sm w-auto"
                      value={sbomFormat}
                      onChange={(e) => setSbomFormat(e.target.value as SBOMFormat)}
                    >
                      <option value="cyclonedx">CycloneDX</option>
                      <option value="spdx">SPDX</option>
                    </select>
                    <button className="btn-primary" onClick={handleExportSBOM}>
                      <Download className="w-4 h-4" />
                      Export
                    </button>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
                  <div className="p-3 bg-background-tertiary rounded-lg">
                    <p className="text-sm text-foreground-secondary">Format</p>
                    <p className="text-lg font-semibold text-foreground capitalize">{sbomFormat}</p>
                  </div>
                  <div className="p-3 bg-background-tertiary rounded-lg">
                    <p className="text-sm text-foreground-secondary">Components</p>
                    <p className="text-lg font-semibold text-foreground">{currentScan.dependencies.length}</p>
                  </div>
                  <div className="p-3 bg-background-tertiary rounded-lg">
                    <p className="text-sm text-foreground-secondary">Generated</p>
                    <p className="text-lg font-semibold text-foreground">
                      {formatDistanceToNow(new Date(currentScan.createdAt), { addSuffix: true })}
                    </p>
                  </div>
                </div>

                <div className="code-block max-h-96 overflow-y-auto">
                  <pre className="text-xs"><code>{JSON.stringify({
                    bomFormat: sbomFormat === 'cyclonedx' ? 'CycloneDX' : undefined,
                    spdxVersion: sbomFormat === 'spdx' ? 'SPDX-2.3' : undefined,
                    components: currentScan.dependencies.map(d => ({
                      name: d.name,
                      version: d.version,
                      type: d.type,
                      purl: d.purl || `pkg:generic/${d.name}@${d.version}`,
                      vulnerabilities: d.vulnerabilities.map(v => v.id)
                    }))
                  }, null, 2)}</code></pre>
                </div>
              </div>
            </>
          )}

          {/* Remediation Modal */}
          {remediation && (
            <div className="modal-overlay" onClick={() => setRemediation(null)}>
              <div className="modal-content w-full max-w-4xl p-6" onClick={(e) => e.stopPropagation()}>
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
                    <Sparkles className="w-5 h-5 text-accent-purple" />
                    AI Remediation: {remediation.dependencyName}
                  </h2>
                  <button className="btn-icon" onClick={() => setRemediation(null)}>
                    <ChevronDown className="w-5 h-5" />
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                  <div className="p-3 bg-background-tertiary rounded-lg">
                    <p className="font-medium text-foreground mb-1">Current Version</p>
                    <p className="font-mono text-sm text-foreground-secondary">{remediation.currentVersion}</p>
                  </div>
                  <div className="p-3 bg-accent-green/10 border border-accent-green/20 rounded-lg">
                    <p className="font-medium text-accent-green mb-1">Recommended Version</p>
                    <p className="font-mono text-sm text-accent-green">{remediation.recommendedVersion}</p>
                  </div>
                </div>

                <div className="space-y-4">
                  <div className="p-3 bg-background-tertiary rounded-lg">
                    <p className="font-medium text-foreground mb-2 flex items-center gap-2">
                      <Zap className="w-4 h-4 text-accent-yellow" />
                      Explanation
                    </p>
                    <p className="text-sm text-foreground-secondary">{remediation.explanation}</p>
                  </div>

                  <div className="p-3 bg-background-tertiary rounded-lg">
                    <p className="font-medium text-foreground mb-2 flex items-center gap-2">
                      <Wrench className="w-4 h-4" />
                      Steps
                    </p>
                    <ol className="list-decimal list-inside text-sm text-foreground-secondary space-y-1">
                      {remediation.steps.map((step, i) => (
                        <li key={i}>{step}</li>
                      ))}
                    </ol>
                  </div>

                  <div className="p-3 bg-background-tertiary rounded-lg">
                    <p className="font-medium text-foreground mb-2 flex items-center gap-2">
                      <Terminal className="w-4 h-4" />
                      Command
                    </p>
                    <div className="code-block">
                      <code className="text-sm font-mono">{remediation.command}</code>
                    </div>
                    <button
                      className="btn-secondary text-xs mt-2"
                      onClick={() => navigator.clipboard.writeText(remediation.command)}
                    >
                      <Copy className="w-3 h-3" />
                      Copy Command
                    </button>
                  </div>

                  {remediation.risks.length > 0 && (
                    <div className="p-3 bg-severity-medium/10 border border-severity-medium/20 rounded-lg">
                      <p className="font-medium text-severity-medium mb-2 flex items-center gap-2">
                        <AlertTriangle className="w-4 h-4" />
                        Risks & Considerations
                      </p>
                      <ul className="text-sm text-foreground-secondary space-y-1">
                        {remediation.risks.map((risk, i) => (
                          <li key={i} className="flex items-start gap-2">
                            <span className="text-severity-medium">•</span>
                            {risk}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>

                <div className="flex gap-2 mt-6">
                  <button className="btn-secondary" onClick={() => setRemediation(null)}>
                    Close
                  </button>
                  <button
                    className="btn-primary"
                    onClick={() => {
                      navigator.clipboard.writeText(remediation.command);
                      toast.success('Command copied to clipboard');
                    }}
                  >
                    <Copy className="w-4 h-4" />
                    Copy Fix Command
                  </button>
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {/* Help Section */}
      <div className="card">
        <h3 className="font-semibold text-foreground mb-4 flex items-center gap-2">
          <Zap className="w-5 h-5 text-accent-yellow" />
          How it works
        </h3>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm text-foreground-secondary">
          <div className="p-3 bg-background-tertiary rounded-lg">
            <Radar className="w-5 h-5 text-accent-blue mb-2" />
            <p className="font-medium text-foreground mb-1">1. Discover</p>
            <p>Syft generates SBOM from repo</p>
          </div>
          <div className="p-3 bg-background-tertiary rounded-lg">
            <Shield className="w-5 h-5 text-accent-green mb-2" />
            <p className="font-medium text-foreground mb-1">2. Scan</p>
            <p>Grype finds vulnerabilities</p>
          </div>
          <div className="p-3 bg-background-tertiary rounded-lg">
            <AlertTriangle className="w-5 h-5 text-accent-purple mb-2" />
            <p className="font-medium text-foreground mb-1">3. Analyze</p>
            <p>Map CVEs to dependencies</p>
          </div>
          <div className="p-3 bg-background-tertiary rounded-lg">
            <Sparkles className="w-5 h-5 text-accent-yellow mb-2" />
            <p className="font-medium text-foreground mb-1">4. Fix</p>
            <p>AI suggests safe upgrades</p>
          </div>
        </div>
      </div>
    </div>
  );
}