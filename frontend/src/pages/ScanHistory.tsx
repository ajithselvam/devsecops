import React, { useState, useCallback, useEffect } from 'react';
import {
  History,
  Search,
  Download,
  Trash2,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Calendar,
  Container,
  FileCode,
  GitBranch,
  Package,
  Server,
  CheckCircle,
  XCircle,
  Clock,
  Eye
} from 'lucide-react';
import { scansApi } from '../services/api';
import { Scan, ScanType, ScanStatus } from '@devsecops/shared/types';
import { toast } from 'react-hot-toast';
import { clsx } from 'clsx';
import { formatDistanceToNow } from 'date-fns';

const TYPE_ICONS: Record<ScanType, React.ComponentType<any>> = {
  dockerfile: FileCode,
  docker_image: Container,
  kubernetes: GitBranch,
  jenkinsfile: Server,
  github_repo: GitBranch,
  logs: FileCode,
  dependency: Package
} as Record<ScanType, React.ComponentType<any>>;

const TYPE_LABELS: Record<ScanType, string> = {
  dockerfile: 'Dockerfile Fix',
  docker_image: 'Image Scan',
  kubernetes: 'K8s YAML',
  jenkinsfile: 'Jenkins',
  github_repo: 'GitHub Security',
  logs: 'Log Investigation',
  dependency: 'Dependency Radar'
} as Record<ScanType, string>;

const STATUS_COLORS: Record<ScanStatus, { text: string; bg: string }> = {
  pending: { text: 'text-accent-yellow', bg: 'bg-accent-yellow/10' },
  running: { text: 'text-accent-blue', bg: 'bg-accent-blue/10' },
  completed: { text: 'text-accent-green', bg: 'bg-accent-green/10' },
  failed: { text: 'text-severity-critical', bg: 'bg-severity-critical/10' },
  cancelled: { text: 'text-foreground-muted', bg: 'bg-background-tertiary' }
};

export function ScanHistory() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  const [pageSize] = useState(20);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<string[]>([]);
  const [filterStatus, setFilterStatus] = useState<string[]>([]);
  const [sortBy, setSortBy] = useState<'createdAt' | 'duration' | 'severity'>('createdAt');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [selectedScans, setSelectedScans] = useState<string[]>([]);
  const [expandedScan, setExpandedScan] = useState<string | null>(null);

  const loadScans = useCallback(async () => {
    setLoading(true);
    try {
      const response = await scansApi.list({
        page,
        pageSize,
        type: filterType.length > 0 ? filterType.join(',') : undefined,
        status: filterStatus.length > 0 ? filterStatus.join(',') : undefined
      });
      if (response.data.success) {
        setScans(response.data.data.scans);
        setTotalPages(response.data.data.totalPages);
        setTotalCount(response.data.data.total);
      }
    } catch (err) {
      toast.error('Failed to load scan history');
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, filterType, filterStatus, searchQuery, sortBy, sortOrder]);

  useEffect(() => {
    loadScans();
  }, [loadScans]);

  const handleDelete = async (id: string) => {
    try {
      const response = await scansApi.delete(id);
      if (response.data.success) {
        setScans(prev => prev.filter(s => s.id !== id));
        setSelectedScans(prev => prev.filter(s => s !== id));
        toast.success('Scan deleted');
      } else {
        toast.error(response.data.error?.message || 'Delete failed');
      }
    } catch (err) {
      toast.error('Failed to delete');
      console.error(err);
    }
  };

  const handleBatchDelete = async () => {
    if (selectedScans.length === 0) return;
    try {
      const response = await scansApi.batchDelete(selectedScans);
      if (response.data.success) {
        setScans(prev => prev.filter(s => !selectedScans.includes(s.id)));
        setSelectedScans([]);
        toast.success(`Deleted ${selectedScans.length} scans`);
      } else {
        toast.error(response.data.error?.message || 'Batch delete failed');
      }
    } catch (err) {
      toast.error('Failed to delete scans');
      console.error(err);
    }
  };

  const handleExport = async (format: 'json' | 'csv') => {
    try {
      const response = await scansApi.export({
        format,
        type: filterType.length > 0 ? filterType : undefined,
        status: filterStatus.length > 0 ? filterStatus : undefined,
        search: searchQuery.trim() || undefined
      });
      if (response.data.success) {
        const blob = new Blob([JSON.stringify(response.data.data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scan-history-${new Date().toISOString().split('T')[0]}.${format}`;
        a.click();
        URL.revokeObjectURL(url);
        toast.success('Export downloaded');
      }
    } catch (err) {
      toast.error('Export failed');
      console.error(err);
    }
  };

  const toggleSelect = (id: string) => {
    setSelectedScans(prev =>
      prev.includes(id) ? prev.filter(s => s !== id) : [...prev, id]
    );
  };

  const toggleExpand = (id: string) => {
    setExpandedScan(prev => prev === id ? null : id);
  };

  const allSelected = scans.length > 0 && selectedScans.length === scans.length;

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Scan History</h1>
          <p className="text-foreground-secondary mt-1">
            View and manage all your security scans
          </p>
        </div>
        <div className="flex gap-2">
          <button className="btn-secondary" onClick={loadScans}>
            <RefreshCw className="w-4 h-4" />
            Refresh
          </button>
          <button className="btn-secondary" onClick={() => handleExport('json')}>
            <Download className="w-4 h-4" />
            Export JSON
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="card">
        <div className="flex flex-col lg:flex-row gap-3 items-start lg:items-center">
          <div className="relative flex-1 min-w-0">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-foreground-muted" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by name, ID, or target..."
              className="input pl-10"
            />
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <select
              className="input w-auto py-2"
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
            >
              <option value="createdAt">Sort: Date</option>
              <option value="duration">Sort: Duration</option>
              <option value="severity">Sort: Severity</option>
            </select>
            <button
              className="btn-secondary px-3 py-2"
              onClick={() => setSortOrder(prev => prev === 'asc' ? 'desc' : 'asc')}
            >
              {sortOrder === 'asc' ? '↑' : '↓'}
            </button>
          </div>
        </div>

        <div className="flex flex-wrap gap-2 mt-3">
          {(Object.keys(TYPE_LABELS) as ScanType[]).map(type => (
            <button
              key={type}
              className={clsx(
                'px-3 py-1.5 rounded-lg text-sm transition-colors flex items-center gap-1.5',
                filterType.includes(type)
                  ? 'bg-accent-blue/20 text-accent-blue border border-accent-blue/30'
                  : 'bg-background-tertiary text-foreground-secondary'
              )}
              onClick={() => {
                setFilterType(prev =>
                  prev.includes(type) ? prev.filter(t => t !== type) : [...prev, type]
                );
                setPage(1);
              }}
            >
              {React.createElement(TYPE_ICONS[type], { className: 'w-3.5 h-3.5' })}
              {TYPE_LABELS[type]}
            </button>
          ))}
          {(['pending', 'running', 'completed', 'failed'] as ScanStatus[]).map(status => (
            <button
              key={status}
              className={clsx(
                'px-3 py-1.5 rounded-lg text-sm transition-colors capitalize',
                filterStatus.includes(status)
                  ? 'bg-accent-blue/20 text-accent-blue border border-accent-blue/30'
                  : 'bg-background-tertiary text-foreground-secondary'
              )}
              onClick={() => {
                setFilterStatus(prev =>
                  prev.includes(status) ? prev.filter(s => s !== status) : [...prev, status]
                );
                setPage(1);
              }}
            >
              {status}
            </button>
          ))}
        </div>

        {selectedScans.length > 0 && (
          <div className="mt-3 flex items-center gap-2 p-2 bg-accent-blue/10 border border-accent-blue/20 rounded-lg">
            <span className="text-sm text-accent-blue font-medium">{selectedScans.length} selected</span>
            <button className="btn-secondary text-sm" onClick={handleBatchDelete}>
              <Trash2 className="w-3.5 h-3.5" />
              Delete Selected
            </button>
            <button className="btn-secondary text-sm" onClick={() => setSelectedScans([])}>
              Clear
            </button>
          </div>
        )}
      </div>

      {/* Results */}
      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="flex flex-col items-center gap-3">
            <div className="w-8 h-8 border-2 border-accent-blue/30 border-t-accent-blue rounded-full animate-spin" />
            <p className="text-foreground-secondary">Loading scans...</p>
          </div>
        </div>
      ) : scans.length === 0 ? (
        <div className="card text-center py-16">
          <History className="w-12 h-12 mx-auto text-foreground-muted mb-4" />
          <p className="text-foreground-secondary">No scans found</p>
          <p className="text-sm text-foreground-muted mt-1">Try adjusting your filters</p>
        </div>
      ) : (
        <>
          <div className="card p-0 overflow-hidden">
            {/* Header row */}
            <div className="hidden md:grid grid-cols-12 gap-4 px-4 py-3 border-b border-border text-sm text-foreground-secondary">
              <div className="col-span-1">
                <input
                  type="checkbox"
                  checked={allSelected}
                  onChange={() => {
                    if (allSelected) setSelectedScans([]);
                    else setSelectedScans(scans.map(s => s.id));
                  }}
                  className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue"
                />
              </div>
              <div className="col-span-3">Scan</div>
              <div className="col-span-2">Type</div>
              <div className="col-span-2">Status</div>
              <div className="col-span-2">Findings</div>
              <div className="col-span-1">Duration</div>
              <div className="col-span-1">Actions</div>
            </div>

            <div className="divide-y divide-border">
              {scans.map(scan => {
                const TypeIcon = TYPE_ICONS[scan.type];
                const statusColor = STATUS_COLORS[scan.status];
                const totalFindings = scan.summary?.totalFindings || 0;
                return (
                  <div key={scan.id} className="hover:bg-background-tertiary/30 transition-colors">
                    <div className="grid grid-cols-1 md:grid-cols-12 gap-4 px-4 py-3 items-center">
                      <div className="col-span-1">
                        <input
                          type="checkbox"
                          checked={selectedScans.includes(scan.id)}
                          onChange={() => toggleSelect(scan.id)}
                          className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue"
                        />
                      </div>
                      <div className="col-span-3 min-w-0">
                        <p className="font-medium text-foreground truncate">{scan.target?.value || 'Unknown'}</p>
                        <p className="text-xs text-foreground-muted font-mono truncate">{scan.id}</p>
                        <p className="text-xs text-foreground-secondary mt-0.5 flex items-center gap-1">
                          <Calendar className="w-3 h-3" />
                          {formatDistanceToNow(new Date(scan.createdAt), { addSuffix: true })}
                        </p>
                      </div>
                      <div className="col-span-2">
                        <span className="badge badge-ghost flex items-center gap-1.5 w-fit">
                          <TypeIcon className="w-3.5 h-3.5" />
                          {TYPE_LABELS[scan.type]}
                        </span>
                      </div>
                      <div className="col-span-2">
                        <span className={clsx('badge flex items-center gap-1.5 w-fit', statusColor.bg, statusColor.text)}>
                          {scan.status === 'completed' && <CheckCircle className="w-3.5 h-3.5" />}
                          {scan.status === 'failed' && <XCircle className="w-3.5 h-3.5" />}
                          {scan.status === 'running' && <Clock className="w-3.5 h-3.5" />}
                          {scan.status === 'pending' && <Clock className="w-3.5 h-3.5" />}
                          <span className="capitalize">{scan.status}</span>
                        </span>
                      </div>
                      <div className="col-span-2">
                        {totalFindings > 0 ? (
                          <div className="flex items-center gap-1 flex-wrap">
                            {scan.summary?.critical > 0 && <span className="badge bg-severity-critical/10 text-severity-critical text-xs">{scan.summary.critical}C</span>}
                            {scan.summary?.high > 0 && <span className="badge bg-severity-high/10 text-severity-high text-xs">{scan.summary.high}H</span>}
                            {scan.summary?.medium > 0 && <span className="badge bg-severity-medium/10 text-severity-medium text-xs">{scan.summary.medium}M</span>}
                            {scan.summary?.low > 0 && <span className="badge bg-severity-low/10 text-severity-low text-xs">{scan.summary.low}L</span>}
                          </div>
                        ) : (
                          <span className="text-foreground-muted text-sm">No findings</span>
                        )}
                      </div>
                      <div className="col-span-1 text-sm text-foreground-secondary">
                        {(scan as any).duration ? `${Math.round((scan as any).duration / 1000)}s` : '-'}
                      </div>
                      <div className="col-span-1 flex items-center gap-1">
                        <button className="btn-icon" onClick={() => toggleExpand(scan.id)}>
                          {expandedScan === scan.id ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                        </button>
                        <button
                          className="btn-icon text-foreground-muted hover:text-severity-critical"
                          onClick={() => handleDelete(scan.id)}
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>

                    {expandedScan === scan.id && (
                      <div className="px-4 pb-4 bg-background-tertiary/50 space-y-3">
                        {scan.target && (
                          <div className="text-sm">
                            <span className="text-foreground-secondary">Target: </span>
                            <span className="font-mono text-foreground">{scan.target.value}</span>
                          </div>
                        )}
                        {scan.target.metadata && Object.keys(scan.target.metadata).length > 0 && (
                          <div className="code-block">
                            <pre className="text-xs"><code>{JSON.stringify(scan.target.metadata, null, 2)}</code></pre>
                          </div>
                        )}
                        {scan.jobId && (
                          <div className="text-sm">
                            <span className="text-foreground-secondary">Job ID: </span>
                            <span className="font-mono text-foreground">{scan.jobId}</span>
                          </div>
                        )}
                        <div className="flex gap-2">
                          <button className="btn-secondary text-sm">
                            <Eye className="w-3.5 h-3.5" />
                            View Details
                          </button>
                          <button
                            className="btn-secondary text-sm"
                            onClick={() => handleExport('json')}
                          >
                            <Download className="w-3.5 h-3.5" />
                            Export
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between">
            <p className="text-sm text-foreground-secondary">
              Showing {((page - 1) * pageSize) + 1} - {Math.min(page * pageSize, totalCount)} of {totalCount}
            </p>
            <div className="flex items-center gap-2">
              <button
                className="btn-secondary"
                disabled={page <= 1}
                onClick={() => setPage(p => Math.max(1, p - 1))}
              >
                Previous
              </button>
              <span className="text-sm text-foreground-secondary px-2">
                Page {page} of {totalPages}
              </span>
              <button
                className="btn-secondary"
                disabled={page >= totalPages}
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              >
                Next
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}