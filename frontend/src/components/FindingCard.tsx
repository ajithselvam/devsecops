import React from 'react';
import { AlertTriangle, FileText, Code, ExternalLink, ChevronDown, ChevronUp } from 'lucide-react';
import { Finding, Severity } from '@devsecops/shared/types';
import { clsx } from 'clsx';

interface FindingCardProps {
  finding: Finding;
  onFix?: (finding: Finding) => void;
  onIgnore?: (finding: Finding) => void;
  expanded?: boolean;
  onToggleExpand?: (finding: Finding) => void;
  showActions?: boolean;
}

const SEVERITY_ICONS: Record<Severity, React.ReactNode> = {
  critical: <AlertTriangle className="w-4 h-4 text-severity-critical" />,
  high: <AlertTriangle className="w-4 h-4 text-severity-high" />,
  medium: <AlertTriangle className="w-4 h-4 text-severity-medium" />,
  low: <AlertTriangle className="w-4 h-4 text-severity-low" />,
  info: <AlertTriangle className="w-4 h-4 text-severity-info" />
};

const SEVERITY_BADGES: Record<Severity, string> = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'badge-info'
};

export function FindingCard({
  finding,
  onFix,
  onIgnore,
  expanded = false,
  onToggleExpand,
  showActions = true
}: FindingCardProps) {
  const getTypeIcon = (type: Finding['type']) => {
    switch (type) {
      case 'vulnerability':
        return <AlertTriangle className="w-4 h-4" />;
      case 'secret':
        return <Code className="w-4 h-4" />;
      case 'misconfiguration':
      case 'bad_practice':
        return <FileText className="w-4 h-4" />;
      default:
        return <AlertTriangle className="w-4 h-4" />;
    }
  };

  return (
    <div className={clsx('card border-l-4', {
      'border-severity-critical': finding.severity === 'critical',
      'border-severity-high': finding.severity === 'high',
      'border-severity-medium': finding.severity === 'medium',
      'border-severity-low': finding.severity === 'low',
      'border-severity-info': finding.severity === 'info',
    })}>
      <div className="flex items-start gap-4">
        <div className="flex-shrink-0 mt-0.5">
          {SEVERITY_ICONS[finding.severity]}
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <h4 className="font-medium text-foreground truncate">{finding.title}</h4>
                <span className={clsx('badge', SEVERITY_BADGES[finding.severity])}>
                  {finding.severity.toUpperCase()}
                </span>
                {finding.type && (
                  <span className="badge badge-info flex items-center gap-1">
                    {getTypeIcon(finding.type)}
                    {finding.type.replace('_', ' ')}
                  </span>
                )}
                {finding.cve && (
                  <a
                    href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${finding.cve}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="badge badge-info flex items-center gap-1 hover:underline"
                  >
                    <ExternalLink className="w-3 h-3" />
                    {finding.cve}
                  </a>
                )}
                {finding.ruleId && (
                  <span className="text-xs text-foreground-muted font-mono">{finding.ruleId}</span>
                )}
              </div>

              <p className="text-sm text-foreground-secondary mt-2">{finding.description}</p>

              {(finding.file || finding.line) && (
                <div className="flex items-center gap-4 mt-2 text-sm text-foreground-muted">
                  {finding.file && (
                    <span className="flex items-center gap-1 font-mono">
                      <FileText className="w-3.5 h-3.5" />
                      {finding.file}
                    </span>
                  )}
                  {finding.line && (
                    <span className="flex items-center gap-1 font-mono">
                      <Code className="w-3.5 h-3.5" />
                      Line {finding.line}
                    </span>
                  )}
                </div>
              )}

              {finding.code && (
                <div className="mt-3">
                  <div className="code-block">
                    <pre className="whitespace-pre-wrap text-sm"><code>{finding.code}</code></pre>
                  </div>
                </div>
              )}

              {finding.references && finding.references.length > 0 && (
                <div className="mt-3">
                  <p className="text-xs font-medium text-foreground-secondary mb-1">References:</p>
                  <div className="flex flex-wrap gap-2">
                    {finding.references.map((ref, i) => (
                      <a
                        key={i}
                        href={ref}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-xs text-accent-blue hover:underline flex items-center gap-1"
                      >
                        <ExternalLink className="w-3 h-3" />
                        {ref.length > 50 ? ref.substring(0, 50) + '...' : ref}
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {finding.remediation && expanded && (
                <div className="mt-4 p-3 bg-background-tertiary rounded-lg border border-border">
                  <div className="flex items-center gap-2 mb-2">
                    <span className="font-medium text-foreground">Remediation</span>
                    {finding.remediation.confidence !== undefined && (
                      <span className="badge badge-success">{finding.remediation.confidence}% confidence</span>
                    )}
                  </div>
                  <p className="text-sm text-foreground-secondary mb-2">{finding.remediation.description}</p>
                  {finding.remediation.steps && finding.remediation.steps.length > 0 && (
                    <ol className="text-sm text-foreground-secondary list-decimal list-inside space-y-1">
                      {finding.remediation.steps.map((step, i) => (
                        <li key={i}>{step}</li>
                      ))}
                    </ol>
                  )}
                  {finding.remediation.breakingChanges && finding.remediation.breakingChanges.length > 0 && (
                    <div className="mt-2 p-2 bg-severity-critical/10 border border-severity-critical/20 rounded">
                      <p className="text-xs font-medium text-severity-critical mb-1">⚠ Breaking Changes:</p>
                      <ul className="text-xs text-foreground-secondary list-disc list-inside space-y-0.5">
                        {finding.remediation.breakingChanges.map((change, i) => (
                          <li key={i}>{change}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {finding.remediation.fixedContent && (
                    <div className="mt-3">
                      <p className="text-xs font-medium text-foreground-secondary mb-1">Fixed Content:</p>
                      <div className="code-block">
                        <pre className="whitespace-pre-wrap text-sm"><code>{finding.remediation.fixedContent}</code></pre>
                      </div>
                    </div>
                  )}
                </div>
              )}

              {finding.remediation && !expanded && finding.remediation.available && (
                <button
                  className="btn-secondary text-sm mt-3"
                  onClick={() => onToggleExpand?.(finding)}
                >
                  <ChevronDown className="w-3.5 h-3.5" />
                  View remediation details
                </button>
              )}
            </div>

            {showActions && finding.remediation?.available && onFix && (
              <div className="flex flex-col gap-2 flex-shrink-0">
                <button
                  className="btn-primary text-sm"
                  onClick={() => onFix(finding)}
                >
                  Fix
                </button>
                {onIgnore && (
                  <button
                    className="btn-secondary text-sm"
                    onClick={() => onIgnore(finding)}
                  >
                    Ignore
                  </button>
                )}
              </div>
            )}
          </div>
        </div>

        {onToggleExpand && (
          <button
            className="flex-shrink-0 p-1 text-foreground-muted hover:text-foreground"
            onClick={() => onToggleExpand(finding)}
            aria-label={expanded ? 'Collapse' : 'Expand'}
          >
            {expanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
          </button>
        )}
      </div>
    </div>
  );
}

export function FindingList({
  findings,
  onFix,
  onIgnore,
  expandedIds = new Set(),
  onToggleExpand,
  showActions = true,
  emptyMessage = 'No findings'
}: {
  findings: Finding[];
  onFix?: (finding: Finding) => void;
  onIgnore?: (finding: Finding) => void;
  expandedIds?: Set<string>;
  onToggleExpand?: (finding: Finding) => void;
  showActions?: boolean;
  emptyMessage?: string;
}) {
  if (findings.length === 0) {
    return (
      <div className="card text-center py-12">
        <AlertTriangle className="w-12 h-12 text-foreground-muted mx-auto mb-4 opacity-50" />
        <p className="text-foreground-secondary">{emptyMessage}</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {findings.map((finding) => (
        <FindingCard
          key={finding.id}
          finding={finding}
          onFix={onFix}
          onIgnore={onIgnore}
          expanded={expandedIds.has(finding.id)}
          onToggleExpand={onToggleExpand}
          showActions={showActions}
        />
      ))}
    </div>
  );
}