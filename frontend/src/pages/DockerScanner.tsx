import React, { useState } from 'react';
import {
  Search,
  Shield,
  Download,
  Copy,
  RefreshCw,
  Filter,
  ChevronDown,
  ChevronUp,
  CheckCircle,
  Package,
  Server,
  Zap,
  ArrowRight,
  History,
  Sparkles,
  ExternalLink
} from 'lucide-react';
import { dockerApi } from '../services/api';
import { DockerImageScanResult, Vulnerability, Severity } from '@devsecops/shared/types';
import { toast } from 'react-hot-toast';
import { formatDistanceToNow } from 'date-fns';
import { clsx } from 'clsx';

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

export function DockerScanner() {
  const [imageRef, setImageRef] = useState('');
  const [scanResult, setScanResult] = useState<DockerImageScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [fixing, setFixing] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState<Severity[]>(['critical', 'high', 'medium', 'low', 'info']);
  const [filterPackage, setFilterPackage] = useState('');
  const [filterCVE, setFilterCVE] = useState('');
  const [showFixableOnly, setShowFixableOnly] = useState(false);
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());
  const [fixResult, setFixResult] = useState<any>(null);
  const [scanHistory, setScanHistory] = useState<Array<{ image: string; result: DockerImageScanResult; timestamp: Date }>>([]);

  const handleScan = async () => {
    if (!imageRef.trim()) {
      toast.error('Please enter a Docker image reference');
      return;
    }

    setLoading(true);
    setFixResult(null);
    try {
      const response = await dockerApi.scan(imageRef.trim());
      if (response.data.success) {
        const result = response.data.data;
        setScanResult(result);
        setScanHistory(prev => [{ image: imageRef.trim(), result, timestamp: new Date() }, ...prev.slice(0, 9)]);
        toast.success(`Scan complete: ${result.vulnerabilities?.length ?? 0} vulnerabilities found`);
      } else {
        toast.error(response.data.error?.message || 'Scan failed');
      }
    } catch (err: any) {
      toast.error(err.response?.data?.error?.message || 'Failed to scan image');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const handleFix = async (vuln?: Vulnerability) => {
    if (!scanResult) return;

    setFixing(true);
    try {
      const vulnsToFix = vuln ? [vuln] : scanResult.vulnerabilities;
      const response = await dockerApi.fix(
        imageRef.trim(),
        vulnsToFix,
        undefined,
        { strategy: 'update_packages', allowBreakingChanges: false }
      );
      if (response.data.success) {
        setFixResult(response.data.data);
        toast.success('Fix generated successfully!');
      } else {
        toast.error(response.data.error?.message || 'Fix failed');
      }
    } catch (err: any) {
      toast.error(err.response?.data?.error?.message || 'Failed to generate fix');
      console.error(err);
    } finally {
      setFixing(false);
    }
  };

  const filteredVulns = scanResult?.vulnerabilities?.filter(v => {
    if (!filterSeverity.includes(v.severity)) return false;
    if (filterPackage && !v.package.toLowerCase().includes(filterPackage.toLowerCase())) return false;
    if (filterCVE && !v.id.toLowerCase().includes(filterCVE.toLowerCase())) return false;
    if (showFixableOnly && !v.fixAvailable) return false;
    return true;
  }) || [];

  const sortedVulns = [...filteredVulns].sort((a, b) =>
    SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]
  );

  const severityCounts = scanResult?.vulnerabilities?.reduce((acc, v) => {
    acc[v.severity] = (acc[v.severity] || 0) + 1;
    return acc;
  }, {} as Record<Severity, number>) || { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  const toggleExpand = (id: string) => {
    setExpandedFindings(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleLoadHistory = (item: typeof scanHistory[0]) => {
    setImageRef(item.image);
    setScanResult(item.result);
    setFixResult(null);
  };

  const handleDownloadCSV = () => {
    if (!scanResult || !scanResult.vulnerabilities || scanResult.vulnerabilities.length === 0) {
      toast.error('No vulnerabilities to export');
      return;
    }

    const headers = [
      'CVE ID',
      'Package',
      'Installed Version',
      'Fixed Version',
      'Severity',
      'CVSS Score',
      'CWE',
      'Type',
      'Fix Available',
      'Description',
      'References'
    ];

    const escapeCsvField = (field: any) => {
      if (field === null || field === undefined) return '""';
      const stringValue = String(field).replace(/"/g, '""');
      return `"${stringValue}"`;
    };

    const rows = scanResult.vulnerabilities.map(v => [
      v.id,
      v.package,
      v.installedVersion,
      v.fixedVersion || 'N/A',
      v.severity.toUpperCase(),
      v.cvssScore !== undefined ? v.cvssScore : 'N/A',
      v.cwe ? `CWE-${v.cwe}` : 'N/A',
      v.type,
      v.fixAvailable ? 'Yes' : 'No',
      v.description,
      (v.references || []).join('; ')
    ].map(escapeCsvField).join(','));

    const csvContent = [headers.map(escapeCsvField).join(','), ...rows].join('\r\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    const sanitizedImageName = scanResult.image.replace(/[^a-zA-Z0-9_.-]/g, '_');
    link.href = url;
    link.setAttribute('download', `docker-cve-report-${sanitizedImageName}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    toast.success('CVE report downloaded as CSV');
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Docker Image Security Scanner</h1>
          <p className="text-foreground-secondary mt-1">
            Scan container images for vulnerabilities using Grype
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button className="btn-secondary" onClick={() => setImageRef('')}>
            <RefreshCw className="w-4 h-4" />
            Clear
          </button>
        </div>
      </div>

      {/* Input Section */}
      <div className="card">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1">
            <label className="label">Docker Image Reference</label>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-foreground-muted" />
              <input
                type="text"
                value={imageRef}
                onChange={(e) => setImageRef(e.target.value)}
                placeholder="e.g., nginx:latest, myorg/myapp:v1.2.3, ghcr.io/user/repo:tag"
                className="input pl-10"
                disabled={loading}
              />
            </div>
            <p className="text-xs text-foreground-muted mt-1">
              Supports Docker Hub, GHCR, ECR, GCR, Quay, and private registries
            </p>
          </div>
          <button
            className="btn-primary self-end"
            onClick={handleScan}
            disabled={loading || !imageRef.trim()}
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                Scanning...
              </>
            ) : (
              <>
                <Shield className="w-4 h-4" />
                Scan Image
              </>
            )}
          </button>
        </div>

        {/* Quick Examples */}
        <div className="mt-4 pt-4 border-t border-border">
          <p className="text-sm text-foreground-secondary mb-2">Quick examples:</p>
          <div className="flex flex-wrap gap-2">
            {[
              'nginx:latest',
              'alpine:latest',
              'ubuntu:22.04',
              'node:20-alpine',
              'python:3.11-slim'
            ].map((img, i) => (
              <button
                key={i}
                className="btn-secondary text-sm px-3 py-1.5"
                onClick={() => setImageRef(img)}
                disabled={loading}
              >
                {img}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Results */}
      {scanResult && (
        <>
          {/* Image Info Card */}
          <div className="card">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-4">
              <div className="flex items-center gap-4">
                <div className="p-3 bg-accent-blue/10 rounded-xl">
                  <Package className="w-6 h-6 text-accent-blue" />
                </div>
                <div>
                  <h2 className="text-xl font-semibold text-foreground font-mono">{scanResult.image}</h2>
                  <div className="flex items-center gap-4 text-sm text-foreground-secondary mt-1">
                    <span className="flex items-center gap-1"><Server className="w-4 h-4" /> {scanResult.os}</span>
                    <span className="flex items-center gap-1"><Package className="w-4 h-4" /> {scanResult.architecture}</span>
                    <span className="flex items-center gap-1"><Package className="w-4 h-4" /> {scanResult.packageCount} packages</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                <button
                  className="btn-secondary flex items-center gap-1.5"
                  onClick={handleDownloadCSV}
                  title="Download CVE Report as CSV"
                >
                  <Download className="w-4 h-4 text-accent-green" />
                  Download CSV
                </button>
                <button className="btn-secondary flex items-center gap-1.5" onClick={() => {
                  navigator.clipboard.writeText(scanResult.digest);
                  toast.success('Digest copied to clipboard');
                }}>
                  <Copy className="w-4 h-4" />
                  Copy Digest
                </button>
                <button className="btn-secondary flex items-center gap-1.5" onClick={handleScan}>
                  <RefreshCw className="w-4 h-4" />
                  Rescan
                </button>
              </div>
            </div>

            {/* Severity Summary */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map(sev => (
                <div
                  key={sev}
                  className={clsx('p-3 rounded-lg text-center', `bg-severity-${sev}/10 border border-severity-${sev}/20`)}
                >
                  <p className="text-2xl font-bold" style={{ color: `var(--color-severity-${sev})` }}>
                    {severityCounts[sev] || 0}
                  </p>
                  <p className="text-xs text-foreground-secondary capitalize">{sev}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Filters */}
          <div className="card">
            <div className="flex flex-wrap items-center gap-4">
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

              <div className="flex items-center gap-2">
                <Search className="w-4 h-4 text-foreground-muted" />
                <input
                  type="text"
                  placeholder="Filter by package..."
                  value={filterPackage}
                  onChange={(e) => setFilterPackage(e.target.value)}
                  className="input py-1.5 px-3 text-sm w-48"
                />
              </div>

              <div className="flex items-center gap-2">
                <Search className="w-4 h-4 text-foreground-muted" />
                <input
                  type="text"
                  placeholder="Filter by CVE..."
                  value={filterCVE}
                  onChange={(e) => setFilterCVE(e.target.value)}
                  className="input py-1.5 px-3 text-sm w-48"
                />
              </div>

              <label className="flex items-center gap-2 text-sm text-foreground-secondary">
                <input
                  type="checkbox"
                  checked={showFixableOnly}
                  onChange={(e) => setShowFixableOnly(e.target.checked)}
                  className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue"
                />
                Fix available only
              </label>

              <div className="flex-1" />
              <span className="text-sm text-foreground-secondary">
                {sortedVulns.length} of {scanResult.vulnerabilities.length} vulnerabilities
              </span>
            </div>
          </div>

          {/* Vulnerability Table */}
          <div className="card p-0 overflow-hidden">
            <div className="p-4 border-b border-border flex items-center justify-between flex-wrap gap-3">
              <div>
                <h3 className="font-semibold text-foreground">Vulnerabilities Detected</h3>
                <p className="text-xs text-foreground-secondary mt-0.5">
                  Showing {sortedVulns.length} of {scanResult.vulnerabilities.length} findings
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  className="btn-secondary text-sm flex items-center gap-1.5"
                  onClick={handleDownloadCSV}
                  title="Download CVE Report as CSV"
                >
                  <Download className="w-4 h-4 text-accent-green" />
                  Download Report (.csv)
                </button>
                {scanResult.vulnerabilities.length > 0 && (
                  <button
                    className="btn-primary text-sm flex items-center gap-2"
                    onClick={() => handleFix()}
                    disabled={fixing}
                  >
                    <Sparkles className="w-4 h-4 text-accent-yellow" />
                    {fixing ? 'Generating Fix...' : 'Fix All Vulnerabilities (AI)'}
                  </button>
                )}
              </div>
            </div>

            {sortedVulns.length === 0 ? (
              <div className="p-12 text-center">
                <CheckCircle className="w-12 h-12 text-accent-green mx-auto mb-4" />
                <h3 className="text-lg font-medium text-foreground mb-1">No vulnerabilities found</h3>
                <p className="text-foreground-secondary">Great! Your image appears clean or matches the active filters.</p>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="table">
                  <thead>
                    <tr>
                      <th className="w-10"></th>
                      <th>CVE</th>
                      <th>Package</th>
                      <th>Installed</th>
                      <th>Fixed</th>
                      <th>Severity</th>
                      <th>Type</th>
                      <th className="text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sortedVulns.map((vuln) => (
                      <React.Fragment key={vuln.id}>
                        <tr className={expandedFindings.has(vuln.id) ? 'bg-background-tertiary/40' : ''}>
                          <td>
                            <button
                              className="text-foreground-muted hover:text-foreground"
                              onClick={() => toggleExpand(vuln.id)}
                            >
                              {expandedFindings.has(vuln.id) ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                            </button>
                          </td>
                          <td>
                            <a
                              href={`https://nvd.nist.gov/vuln/detail/${vuln.id}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="font-mono text-sm hover:underline flex items-center gap-1 text-accent-blue"
                            >
                              {vuln.id}
                              <ExternalLink className="w-3 h-3 opacity-60" />
                            </a>
                          </td>
                          <td className="font-mono text-sm font-medium">{vuln.package}</td>
                          <td className="font-mono text-sm text-foreground-secondary">{vuln.installedVersion}</td>
                          <td className="font-mono text-sm">
                            {vuln.fixedVersion ? (
                              <span className="text-accent-green font-medium">{vuln.fixedVersion}</span>
                            ) : (
                              <span className="text-foreground-muted">No fix available</span>
                            )}
                          </td>
                          <td>
                            <span className={clsx('badge', `badge-${vuln.severity}`)}>
                              {vuln.severity.toUpperCase()}
                            </span>
                          </td>
                          <td>
                            <span className="badge badge-info text-xs uppercase">{vuln.type}</span>
                          </td>
                          <td className="text-right">
                            <button
                              className="btn-primary text-xs px-2.5 py-1"
                              onClick={() => handleFix(vuln)}
                              disabled={fixing}
                            >
                              Fix
                            </button>
                          </td>
                        </tr>
                        {expandedFindings.has(vuln.id) && (
                          <tr key={`expanded-${vuln.id}`} className="bg-background-tertiary/50">
                            <td colSpan={8} className="px-6 py-4">
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                                <div>
                                  <p className="font-medium text-foreground mb-1">Description</p>
                                  <p className="text-foreground-secondary leading-relaxed">{vuln.description}</p>
                                </div>
                                <div className="space-y-2">
                                  <div>
                                    <p className="font-medium text-foreground mb-1">CVSS Score & CWE</p>
                                    <p className="text-foreground-secondary">
                                      {vuln.cvssScore ? (
                                        <span className="font-semibold text-foreground">{vuln.cvssScore.toFixed(1)} / 10</span>
                                      ) : 'N/A'}
                                      {vuln.cwe && <span className="ml-2 font-mono text-xs bg-background-elevated px-2 py-0.5 rounded">CWE-{vuln.cwe}</span>}
                                    </p>
                                  </div>
                                  {vuln.references && vuln.references.length > 0 && (
                                    <div>
                                      <p className="font-medium text-foreground mb-1">References</p>
                                      <div className="flex flex-wrap gap-2">
                                        {vuln.references.slice(0, 4).map((ref, i) => (
                                          <a
                                            key={i}
                                            href={ref}
                                            target="_blank"
                                            rel="noopener noreferrer"
                                            className="text-xs text-accent-blue hover:underline max-w-xs truncate"
                                          >
                                            {ref}
                                          </a>
                                        ))}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Fix Result */}
          {fixResult && (
            <div className="card border-l-4 border-accent-green">
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 bg-accent-green/10 rounded-lg">
                  <CheckCircle className="w-5 h-5 text-accent-green" />
                </div>
                <div>
                  <h3 className="font-semibold text-foreground">Fix Generated</h3>
                  <p className="text-sm text-foreground-secondary">AI has generated a remediation for the selected vulnerability</p>
                </div>
              </div>
              <div className="space-y-3">
                {fixResult.fixedDockerfile && (
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <p className="font-medium text-foreground">Fixed Dockerfile</p>
                      <div className="flex gap-2">
                        <button className="btn-secondary text-sm" onClick={() => navigator.clipboard.writeText(fixResult.fixedDockerfile)}>
                          <Copy className="w-3.5 h-3.5" />
                        </button>
                        <button className="btn-secondary text-sm" onClick={() => {
                          const blob = new Blob([fixResult.fixedDockerfile], { type: 'text/plain' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          a.download = 'Dockerfile.fixed';
                          a.click();
                          URL.revokeObjectURL(url);
                        }}>
                          <Download className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    </div>
                    <div className="code-block max-h-64 overflow-auto">
                      <pre className="whitespace-pre-wrap text-sm"><code>{fixResult.fixedDockerfile}</code></pre>
                    </div>
                  </div>
                )}
                {fixResult.beforeVulnerabilities && fixResult.afterVulnerabilities && (
                  <div className="grid grid-cols-2 gap-4">
                    <div className="p-3 bg-severity-critical/10 rounded-lg border border-severity-critical/20">
                      <p className="font-medium text-severity-critical mb-2">Before Fix</p>
                      <div className="flex gap-2">
                        <span className="badge badge-critical">Critical: {fixResult.beforeVulnerabilities.filter((v: any) => v.severity === 'critical').length}</span>
                        <span className="badge badge-high">High: {fixResult.beforeVulnerabilities.filter((v: any) => v.severity === 'high').length}</span>
                        <span className="badge badge-medium">Medium: {fixResult.beforeVulnerabilities.filter((v: any) => v.severity === 'medium').length}</span>
                        <span className="badge badge-low">Low: {fixResult.beforeVulnerabilities.filter((v: any) => v.severity === 'low').length}</span>
                      </div>
                    </div>
                    <div className="p-3 bg-accent-green/10 rounded-lg border border-accent-green/20">
                      <p className="font-medium text-accent-green mb-2">After Fix</p>
                      <div className="flex gap-2">
                        <span className="badge badge-critical">Critical: {fixResult.afterVulnerabilities.filter((v: any) => v.severity === 'critical').length}</span>
                        <span className="badge badge-high">High: {fixResult.afterVulnerabilities.filter((v: any) => v.severity === 'high').length}</span>
                        <span className="badge badge-medium">Medium: {fixResult.afterVulnerabilities.filter((v: any) => v.severity === 'medium').length}</span>
                        <span className="badge badge-low">Low: {fixResult.afterVulnerabilities.filter((v: any) => v.severity === 'low').length}</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Scan History */}
          {scanHistory.length > 0 && (
            <div className="card">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
                  <History className="w-5 h-5" />
                  Recent Scans
                </h2>
                <button className="btn-secondary text-sm" onClick={() => setScanHistory([])}>
                  Clear
                </button>
              </div>
              <div className="space-y-2">
                {scanHistory.map((item, i) => (
                  <button
                    key={i}
                    className="w-full text-left p-3 bg-background-tertiary rounded-lg hover:bg-background-elevated transition-colors flex items-center justify-between"
                    onClick={() => handleLoadHistory(item)}
                  >
                    <div className="flex items-center gap-3">
                      <Package className="w-5 h-5 text-accent-blue" />
                      <div>
                        <p className="font-mono text-sm text-foreground">{item.image}</p>
                        <p className="text-xs text-foreground-secondary">
                          {item.result.vulnerabilities.length} vulns • {formatDistanceToNow(item.timestamp, { addSuffix: true })}
                        </p>
                      </div>
                    </div>
                    <ArrowRight className="w-4 h-4 text-foreground-muted" />
                  </button>
                ))}
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
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm text-foreground-secondary">
          <div className="p-3 bg-background-tertiary rounded-lg">
            <h4 className="font-medium text-foreground mb-1">1. Pull & Analyze</h4>
            <p>Grype pulls image metadata and scans all packages against vulnerability databases</p>
          </div>
          <div className="p-3 bg-background-tertiary rounded-lg">
            <h4 className="font-medium text-foreground mb-1">2. AI Remediation</h4>
            <p>AI analyzes each vulnerability and generates fixes: package updates, base image changes, or removals</p>
          </div>
          <div className="p-3 bg-background-tertiary rounded-lg">
            <h4 className="font-medium text-foreground mb-1">3. Build & Verify</h4>
            <p>Fixed image is built, rescanned, and compared to show before/after vulnerability counts</p>
          </div>
        </div>
      </div>
    </div>
  );
}