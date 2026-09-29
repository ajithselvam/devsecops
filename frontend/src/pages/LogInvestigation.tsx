import React, { useEffect, useState, useRef } from 'react';
import {
  Upload,
  Download,
  Trash2,
  Search,
  Filter,
  Sparkles,
  AlertTriangle,
  CheckCircle,
  Clock,
  FileText,
  Server,
  Database,
  ChevronDown,
  ChevronUp,
  MessageSquare,
  Zap
} from 'lucide-react';
import { logsApi } from '../services/api';
import { LogFile, LogEntry, LogInvestigationResult } from '@devsecops/shared/types';
import { toast } from 'react-hot-toast';
import { formatDistanceToNow } from 'date-fns';
import { clsx } from 'clsx';


const LEVEL_COLORS: Record<string, string> = {
  fatal: 'text-severity-critical',
  error: 'text-severity-high',
  warn: 'text-severity-medium',
  info: 'text-severity-low',
  debug: 'text-severity-info',
  trace: 'text-foreground-muted'
};

const SAMPLE_QUESTIONS = [
  'Why did the application fail yesterday?',
  'How many 500 errors occurred?',
  'Which IP generated the most requests?',
  'Which service has the highest error rate?',
  'What caused the spike at 14:30?',
  'Show all authentication failures',
  'Find suspicious IP addresses',
  'What is the root cause of the database connection errors?',
  'Summarize the error patterns in the last hour',
  'Which endpoints are failing most frequently?'
];

export function LogInvestigation() {
  const [logFiles, setLogFiles] = useState<LogFile[]>([]);
  const [selectedLogFiles, setSelectedLogFiles] = useState<string[]>([]);
  const [uploading, setUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState<any>(null);
  const [searching, setSearching] = useState(false);
  const [investigationQuestion, setInvestigationQuestion] = useState('');
  const [investigating, setInvestigating] = useState(false);
  const [investigationResult, setInvestigationResult] = useState<LogInvestigationResult | null>(null);
  const [activeTab, setActiveTab] = useState<'upload' | 'search' | 'investigate'>('upload');
  const [filterLevel, setFilterLevel] = useState<string[]>([]);
  const [filterService, setFilterService] = useState<string[]>([]);
  const [timeRange, setTimeRange] = useState<{ start: Date | null; end: Date | null }>({ start: null, end: null });
  const [expandedEntries, setExpandedEntries] = useState<Set<string>>(new Set());
  const fileInputRef = useRef<HTMLInputElement>(null);

  const apiError = (err: any, fallback: string) =>
    err?.response?.data?.error?.message || fallback;

  useEffect(() => {
    logsApi.list()
      .then((res) => {
        if (res.data.success) setLogFiles(res.data.data || []);
      })
      .catch((err) => console.error(err));
  }, []);

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (!files || files.length === 0) return;

    setUploading(true);
    setUploadProgress(0);

    for (const file of Array.from(files)) {
      try {
        const response = await logsApi.upload(file, setUploadProgress);
        if (response.data.success) {
          setLogFiles(prev => [response.data.data, ...prev]);
          toast.success(`Uploaded: ${file.name}`);
        } else {
          toast.error(response.data.error?.message || `Failed to upload ${file.name}`);
        }
      } catch (err) {
        toast.error(apiError(err, `Failed to upload ${file.name}`));
        console.error(err);
      }
    }
    setUploading(false);
    setUploadProgress(0);
    event.target.value = '';
  };

  const handleDeleteLog = async (id: string) => {
    try {
      const response = await logsApi.delete(id);
      if (response.data.success) {
        setLogFiles(prev => prev.filter(f => f.id !== id));
        setSelectedLogFiles(prev => prev.filter(f => f !== id));
        toast.success('Log file deleted');
      } else {
        toast.error(response.data.error?.message || 'Delete failed');
      }
    } catch (err) {
      toast.error(apiError(err, 'Failed to delete'));
      console.error(err);
    }
  };

  const handleSearch = async () => {
    if (!searchQuery.trim() && selectedLogFiles.length === 0) {
      toast.error('Select at least one log file or enter a search query');
      return;
    }
    setSearching(true);
    try {
      const response = await logsApi.search(
        searchQuery,
        selectedLogFiles,
        timeRange.start && timeRange.end ? { start: timeRange.start.toISOString(), end: timeRange.end.toISOString() } : undefined,
        filterLevel.length > 0 ? filterLevel : undefined,
        filterService.length > 0 ? filterService : undefined
      );
      if (response.data.success) {
        setSearchResults(response.data.data);
        setActiveTab('search');
        toast.success(`Found ${response.data.data.total ?? 0} entries`);
      } else {
        toast.error(response.data.error?.message || 'Search failed');
      }
    } catch (err) {
      toast.error(apiError(err, 'Search failed'));
      console.error(err);
    } finally {
      setSearching(false);
    }
  };

  const handleInvestigate = async (questionOverride?: string) => {
    const question = (questionOverride ?? investigationQuestion).trim();
    if (!question || selectedLogFiles.length === 0) {
      toast.error('Enter a question and select log files');
      return;
    }
    if (questionOverride) setInvestigationQuestion(questionOverride);
    setInvestigating(true);
    try {
      const response = await logsApi.investigate(
        question,
        selectedLogFiles,
        timeRange.start && timeRange.end ? { start: timeRange.start.toISOString(), end: timeRange.end.toISOString() } : undefined
      );
      if (response.data.success) {
        const data = response.data.data;
        setInvestigationResult({
          question,
          rootCause: data.rootCause || 'No root cause identified',
          evidence: data.evidence || [],
          timeline: data.timeline || [],
          affectedServices: data.affectedServices || [],
          errorPatterns: data.errorPatterns || [],
          recommendedActions: data.recommendedActions || [],
          confidence: data.confidence ?? 0,
          analyzedEntries: data.analyzedEntries ?? 0,
          analysisTime: data.analysisTime || new Date().toISOString()
        });
        toast.success('Investigation complete!');
      } else {
        toast.error(response.data.error?.message || 'Investigation failed');
      }
    } catch (err) {
      toast.error(apiError(err, 'Investigation failed'));
      console.error(err);
    } finally {
      setInvestigating(false);
    }
  };

  const toggleLogSelection = (id: string) => {
    setSelectedLogFiles(prev =>
      prev.includes(id) ? prev.filter(f => f !== id) : [...prev, id]
    );
  };

  const toggleExpand = (id: string) => {
    setExpandedEntries(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const getAvailableServices = () => {
    const services = new Set<string>();
    logFiles.forEach(f => (f as any).services?.forEach((s: string) => services.add(s)));
    return Array.from(services);
  };

  const getAvailableLevels = () => ['fatal', 'error', 'warn', 'info', 'debug', 'trace'];

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground">AI Log Investigation</h1>
          <p className="text-foreground-secondary mt-1">
            Upload, search, and analyze logs with natural language queries
          </p>
        </div>
      </div>

      {/* Tabs */}
      <div className="tabs">
        <button className={clsx('tab', activeTab === 'upload' && 'tab-active')} onClick={() => setActiveTab('upload')}>
          <Upload className="w-4 h-4" />
          Upload Logs
        </button>
        <button className={clsx('tab', activeTab === 'search' && 'tab-active')} onClick={() => setActiveTab('search')}>
          <Search className="w-4 h-4" />
          Search
        </button>
        <button className={clsx('tab', activeTab === 'investigate' && 'tab-active')} onClick={() => setActiveTab('investigate')}>
          <Sparkles className="w-4 h-4" />
          AI Investigate
        </button>
      </div>

      {/* Upload Tab */}
      {activeTab === 'upload' && (
        <>
          <div className="card">
            <div className="mb-4">
              <label className="label">Upload Log Files</label>
              <div
                className="border-2 border-dashed border-border rounded-lg p-8 text-center hover:border-accent-blue transition-colors relative"
                onClick={() => fileInputRef.current?.click()}
                onDragOver={(e) => { e.preventDefault(); e.currentTarget.classList.add('border-accent-blue'); }}
                onDragLeave={(e) => { e.currentTarget.classList.remove('border-accent-blue'); }}
                onDrop={(e) => {
                  e.preventDefault();
                  e.currentTarget.classList.remove('border-accent-blue');
                  if (e.dataTransfer.files.length > 0) {
                    handleFileUpload({ target: { files: e.dataTransfer.files } } as any);
                  }
                }}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".log,.txt,.json,.gz"
                  multiple
                  onChange={handleFileUpload}
                  className="hidden"
                />
                <Upload className="w-12 h-12 mx-auto text-foreground-muted mb-4" />
                <p className="text-foreground">Drag & drop log files here, or click to browse</p>
                <p className="text-sm text-foreground-muted mt-1">Supports: .log, .txt, .json, .gz (max 25MB each)</p>
                {uploading && (
                  <div className="mt-4">
                    <div className="progress-bar mx-auto max-w-md">
                      <div className="progress-fill bg-accent-blue" style={{ width: `${uploadProgress}%` }} />
                    </div>
                    <p className="text-sm text-foreground-secondary mt-2">{uploadProgress}%</p>
                  </div>
                )}
              </div>
            </div>

            {logFiles.length > 0 && (
              <div>
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-medium text-foreground">Uploaded Log Files</h3>
                  <span className="text-sm text-foreground-secondary">{logFiles.length} files</span>
                </div>
                <div className="space-y-2">
                  {logFiles.map((log) => (
                    <div
                      key={log.id}
                      className={clsx(
                        'p-3 bg-background-tertiary rounded-lg flex items-center justify-between transition-colors',
                        selectedLogFiles.includes(log.id) ? 'bg-accent-blue/10 border border-accent-blue/20' : ''
                      )}
                    >
                      <div className="flex items-center gap-3 flex-1 min-w-0">
                        <input
                          type="checkbox"
                          checked={selectedLogFiles.includes(log.id)}
                          onChange={() => toggleLogSelection(log.id)}
                          className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue mt-0.5"
                        />
                        <FileText className="w-5 h-5 text-accent-blue" />
                        <div className="min-w-0">
                          <p className="font-mono text-sm text-foreground truncate">{log.name}</p>
                          <p className="text-xs text-foreground-secondary">
                            {log.lineCount.toLocaleString()} lines • {formatDistanceToNow(new Date((log as any).uploadedAt || (log as any).createdAt), { addSuffix: true })}
                            {log.indexed && <span className="ml-2 badge badge-success">Indexed</span>}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-foreground-muted font-mono">
                          {log.format}
                        </span>
                        <button
                          className="btn-icon p-1.5 text-foreground-muted hover:text-severity-critical"
                          onClick={() => handleDeleteLog(log.id)}
                          disabled={uploading}
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {selectedLogFiles.length > 0 && (
              <div className="mt-4 p-3 bg-accent-blue/10 border border-accent-blue/20 rounded-lg">
                <p className="font-medium text-accent-blue mb-2">{selectedLogFiles.length} file(s) selected</p>
                <div className="flex gap-2">
                  <button className="btn-primary" onClick={() => setActiveTab('search')}>
                    <Search className="w-4 h-4" />
                    Search Logs
                  </button>
                  <button className="btn-primary" onClick={() => setActiveTab('investigate')}>
                    <Sparkles className="w-4 h-4" />
                    AI Investigate
                  </button>
                </div>
              </div>
            )}
          </div>
        </>
      )}

      {/* Search Tab */}
      {activeTab === 'search' && (
        <>
          <div className="card">
            <div className="mb-4">
              <label className="label">Search Query</label>
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-foreground-muted" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search logs... (e.g., error, timeout, 500, connection refused)"
                  className="input pl-10"
                />
              </div>
            </div>

            <div className="flex flex-wrap gap-4 mb-4">
              <div className="flex items-center gap-2">
                <Filter className="w-4 h-4 text-foreground-muted" />
                <select
                  className="input py-1.5 px-3 text-sm w-auto"
                  multiple
                  value={filterLevel}
                  onChange={(e) => {
                    const selected = Array.from(e.target.selectedOptions).map(o => o.value);
                    setFilterLevel(selected);
                  }}
                >
                  {getAvailableLevels().map(l => (
                    <option key={l} value={l} className="capitalize">{l}</option>
                  ))}
                </select>
              </div>
              <div className="flex items-center gap-2">
                <Filter className="w-4 h-4 text-foreground-muted" />
                <select
                  className="input py-1.5 px-3 text-sm w-auto"
                  multiple
                  value={filterService}
                  onChange={(e) => {
                    const selected = Array.from(e.target.selectedOptions).map(o => o.value);
                    setFilterService(selected);
                  }}
                >
                  {getAvailableServices().map(s => (
                    <option key={s} value={s}>{s}</option>
                  ))}
                </select>
              </div>
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-foreground-muted" />
                <input
                  type="datetime-local"
                  value={timeRange.start ? timeRange.start.toISOString().slice(0, 16) : ''}
                  onChange={(e) => setTimeRange({ ...timeRange, start: e.target.value ? new Date(e.target.value) : null })}
                  className="input py-1.5 px-3 text-sm w-auto"
                />
                <span className="text-foreground-muted">to</span>
                <input
                  type="datetime-local"
                  value={timeRange.end ? timeRange.end.toISOString().slice(0, 16) : ''}
                  onChange={(e) => setTimeRange({ ...timeRange, end: e.target.value ? new Date(e.target.value) : null })}
                  className="input py-1.5 px-3 text-sm w-auto"
                />
              </div>
            </div>

            <button className="btn-primary" onClick={handleSearch} disabled={searching || (!searchQuery.trim() && selectedLogFiles.length === 0)}>
              {searching ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Searching...
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  Search
                </>
              )}
            </button>
          </div>

          {searchResults && (
            <div className="card">
              <div className="flex items-center justify-between mb-4">
                <h3 className="font-medium text-foreground">Results ({searchResults.total})</h3>
                <div className="flex gap-2">
                  <button className="btn-secondary text-sm">
                    <Download className="w-3.5 h-3.5" />
                    Export
                  </button>
                </div>
              </div>
              <div className="max-h-96 overflow-y-auto">
                {searchResults.entries?.map((entry: LogEntry) => (
                  <div
                    key={entry.id}
                    className={clsx(
                      'p-3 border-b border-border/50 hover:bg-background-tertiary/50 transition-colors cursor-pointer',
                      expandedEntries.has(entry.id) ? 'bg-background-tertiary/50' : ''
                    )}
                    onClick={() => toggleExpand(entry.id)}
                  >
                    <div className="flex items-start gap-3">
                      <span
                        className={clsx('px-2 py-0.5 rounded text-xs font-mono font-medium flex-shrink-0', LEVEL_COLORS[entry.level])}
                      >
                        {entry.level.toUpperCase()}
                      </span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 text-sm">
                          <span className="font-mono text-foreground">{entry.timestamp}</span>
                          {entry.service && (
                            <span className="badge badge-info">{entry.service}</span>
                          )}
                        </div>
                        <p className="text-foreground-secondary text-sm mt-1 truncate">{entry.message}</p>
                        {expandedEntries.has(entry.id) && (
                          <div className="mt-2 code-block">
                            <pre className="whitespace-pre-wrap text-xs"><code>{JSON.stringify(entry.fields, null, 2)}</code></pre>
                          </div>
                        )}
                      </div>
                      {expandedEntries.has(entry.id) ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}

      {/* Investigate Tab */}
      {activeTab === 'investigate' && (
        <>
          <div className="card">
            <div className="mb-4">
              <label className="label">Ask a question about your logs</label>
              <textarea
                value={investigationQuestion}
                onChange={(e) => setInvestigationQuestion(e.target.value)}
                placeholder="e.g., Why did the application fail yesterday? What caused the spike at 14:30?"
                className="input min-h-[100px] resize-y"
                rows={3}
              />
            </div>

            <div className="mb-4">
              <p className="label">Suggested questions</p>
              <div className="flex flex-wrap gap-2">
                {SAMPLE_QUESTIONS.map((q, i) => (
                  <button
                    key={i}
                    className="btn-secondary text-sm px-3 py-1.5"
                    onClick={() => setInvestigationQuestion(q)}
                    disabled={investigating}
                  >
                    {q}
                  </button>
                ))}
              </div>
            </div>

            <button
              className="btn-primary w-full"
              onClick={() => handleInvestigate()}
              disabled={investigating || !investigationQuestion.trim() || selectedLogFiles.length === 0}
            >
              {investigating ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Investigating...
                </>
              ) : (
                <>
                  <Sparkles className="w-4 h-4" />
                  Investigate
                </>
              )}
            </button>

            <p className="text-xs text-foreground-muted text-center mt-2">
              {selectedLogFiles.length} log file(s) selected for analysis
            </p>
          </div>

          {investigationResult && (
            <div className="card border-l-4 border-accent-purple">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-semibold text-foreground flex items-center gap-2">
                  <Sparkles className="w-5 h-5 text-accent-purple" />
                  Investigation Result
                </h2>
                <span className="badge badge-success">{investigationResult.confidence}% confidence</span>
              </div>

              <div className="space-y-4">
                <div className="p-3 bg-background-tertiary rounded-lg">
                  <p className="font-medium text-foreground mb-1">Root Cause</p>
                  <p className="text-foreground-secondary">{investigationResult.rootCause}</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="p-3 bg-background-tertiary rounded-lg">
                    <p className="font-medium text-foreground mb-2 flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4" />
                      Affected Services ({investigationResult.affectedServices?.length || 0})
                    </p>
                    <ul className="text-sm text-foreground-secondary space-y-1">
                      {investigationResult.affectedServices?.map((s, i) => (
                        <li key={i} className="flex items-center gap-2">
                          <Server className="w-3.5 h-3.5" />
                          {s}
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="p-3 bg-background-tertiary rounded-lg">
                    <p className="font-medium text-foreground mb-2 flex items-center gap-2">
                      <Clock className="w-4 h-4" />
                      Timeline
                    </p>
                    <ul className="text-sm text-foreground-secondary space-y-2 max-h-48 overflow-y-auto">
                      {investigationResult.timeline?.map((event, i) => (
                        <li key={i} className="flex items-start gap-2 p-2 bg-background rounded">
                          <span className="text-xs text-foreground-muted font-mono min-w-[150px]">{event.timestamp}</span>
                          <div className="flex-1">
                            <p className="font-medium text-foreground">{event.event}</p>
                            {event.service && <p className="text-xs text-foreground-muted">{event.service}</p>}
                          </div>
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                <div className="p-3 bg-background-tertiary rounded-lg">
                  <p className="font-medium text-foreground mb-2 flex items-center gap-2">
                    <Database className="w-4 h-4" />
                    Error Patterns
                  </p>
                  <div className="space-y-2">
                    {investigationResult.errorPatterns?.map((pattern, i) => (
                      <div key={i} className="p-2 bg-background rounded border border-border/50">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-sm text-foreground">{pattern.pattern}</span>
                          <span className="badge badge-info">{pattern.count} occurrences</span>
                        </div>
                        <p className="text-xs text-foreground-muted mt-1">
                          First: {pattern.firstSeen ? formatDistanceToNow(new Date(pattern.firstSeen), { addSuffix: true }) : 'n/a'}, Last: {pattern.lastSeen ? formatDistanceToNow(new Date(pattern.lastSeen), { addSuffix: true }) : 'n/a'}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="p-3 bg-accent-green/10 border border-accent-green/20 rounded-lg">
                  <p className="font-medium text-accent-green mb-2 flex items-center gap-2">
                    <CheckCircle className="w-4 h-4" />
                    Recommended Actions
                  </p>
                  <ol className="list-decimal list-inside text-sm text-foreground-secondary space-y-1">
                    {investigationResult.recommendedActions?.map((action, i) => (
                      <li key={i}>{action}</li>
                    ))}
                  </ol>
                </div>

                <div className="p-3 bg-background-tertiary rounded-lg text-sm text-foreground-secondary">
                  <p>Analyzed {investigationResult.analyzedEntries} log entries</p>
                </div>
              </div>
            </div>
          )}

          {investigationResult && (
            <div className="card">
              <h3 className="font-medium text-foreground mb-4 flex items-center gap-2">
                <MessageSquare className="w-5 h-5 text-accent-purple" />
                Follow-up Questions
              </h3>
              <div className="space-y-2">
                {[
                  'Can you provide more details on the root cause?',
                  'What specific code changes would fix this?',
                  'How can we prevent this from happening again?',
                  'What monitoring alerts should we set up?'
                ].map((q, i) => (
                  <button
                    key={i}
                    className="w-full text-left p-3 bg-background-tertiary rounded-lg text-sm text-foreground-secondary hover:text-foreground hover:bg-background-elevated transition-colors"
                    onClick={() => { handleInvestigate(q); }}
                  >
                    {q}
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
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 text-sm text-foreground-secondary">
          <div className="p-3 bg-background-tertiary rounded-lg">
            <FileText className="w-5 h-5 text-accent-blue mb-2" />
            <p className="font-medium text-foreground mb-1">1. Upload</p>
            <p>Upload log files (auto-parsed & indexed)</p>
          </div>
          <div className="p-3 bg-background-tertiary rounded-lg">
            <Search className="w-5 h-5 text-accent-green mb-2" />
            <p className="font-medium text-foreground mb-1">2. Search</p>
            <p>Full-text search with filters</p>
          </div>
          <div className="p-3 bg-background-tertiary rounded-lg">
            <Sparkles className="w-5 h-5 text-accent-purple mb-2" />
            <p className="font-medium text-foreground mb-1">3. Investigate</p>
            <p>Ask natural language questions</p>
          </div>
          <div className="p-3 bg-background-tertiary rounded-lg">
            <Zap className="w-5 h-5 text-accent-yellow mb-2" />
            <p className="font-medium text-foreground mb-1">4. Fix</p>
            <p>Get root cause, timeline & actions</p>
          </div>
        </div>
      </div>
    </div>
  );
}