import { useMemo, useState } from 'react';
import { DiffChange } from '@devsecops/shared/types';
import { clsx } from 'clsx';

interface DiffViewerProps {
  original: string;
  fixed: string;
  changes: DiffChange[];
  onApplyFixed?: () => void;
  onReset?: () => void;
  showActions?: boolean;
  readOnly?: boolean;
}

export function DiffViewer({
  original,
  fixed,
  changes,
  onApplyFixed,
  onReset,
  showActions = true,
  readOnly = false
}: DiffViewerProps) {
  const [viewMode, setViewMode] = useState<'side-by-side' | 'unified'>('side-by-side');
  const [showLineNumbers, setShowLineNumbers] = useState(true);

  const originalLines = useMemo(() => original.split('\n'), [original]);
  const fixedLines = useMemo(() => fixed.split('\n'), [fixed]);

  const changeMap = useMemo(() => {
    const map = new Map<number, DiffChange>();
    changes.forEach(change => {
      if (change.originalLine) map.set(change.originalLine, change);
      if (change.fixedLine) map.set(change.fixedLine, change);
    });
    return map;
  }, [changes]);

  const getLineClass = (lineNum: number, _isOriginal: boolean) => {
    const change = changeMap.get(lineNum);
    if (!change) return 'line-unchanged';
    if (change.type === 'added') return 'line-added';
    if (change.type === 'removed') return 'line-removed';
    return 'line-modified';
  };

  const renderLineNumber = (num: number, className: string) => (
    <span className={clsx('w-8 text-right pr-3 text-foreground-muted select-none', className)}>
      {num}
    </span>
  );

  const renderLineContent = (content: string, change?: DiffChange, isOriginal = true) => {
    if (!change) return <span className="line-unchanged">{content || ' '}</span>;

    if (change.type === 'modified' && change.originalContent !== change.fixedContent) {
      // Show inline diff
      return (
        <span className={clsx('relative', isOriginal ? 'line-removed' : 'line-added')}>
          {isOriginal ? (
            <>
              <span className="inline-removed">{change.originalContent}</span>
              <span className="inline-added hidden">{change.fixedContent}</span>
            </>
          ) : (
            <>
              <span className="inline-removed hidden">{change.originalContent}</span>
              <span className="inline-added">{change.fixedContent}</span>
            </>
          )}
        </span>
      );
    }

    return <span className={clsx(isOriginal ? 'line-removed' : 'line-added')}>{content || ' '}</span>;
  };

  const isUnified = viewMode === 'unified';

  if (isUnified) {
    return (
      <div className="diff-view font-mono text-sm bg-background-tertiary border border-border rounded-lg overflow-hidden">
        {showActions && !readOnly && (
          <div className="flex items-center gap-2 p-3 border-b border-border bg-background-secondary">
            <div className="flex items-center gap-1 border border-border rounded px-2">
              <button
                className={clsx('px-2 py-1 text-xs rounded', !isUnified ? 'bg-accent-blue/20 text-accent-blue' : 'text-foreground-secondary hover:text-foreground')}
                onClick={() => setViewMode('side-by-side')}
              >
                Side by Side
              </button>
              <button
                className={clsx('px-2 py-1 text-xs rounded', isUnified ? 'bg-accent-blue/20 text-accent-blue' : 'text-foreground-secondary hover:text-foreground')}
                onClick={() => setViewMode('unified')}
              >
                Unified
              </button>
            </div>
            <label className="flex items-center gap-1 text-sm text-foreground-secondary">
              <input
                type="checkbox"
                checked={showLineNumbers}
                onChange={(e) => setShowLineNumbers(e.target.checked)}
                className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue"
              />
              Line numbers
            </label>
            <div className="flex-1" />
            {onApplyFixed && (
              <button className="btn-primary" onClick={onApplyFixed}>
                Apply Fixed Version
              </button>
            )}
            {onReset && (
              <button className="btn-secondary" onClick={onReset}>
                Reset
              </button>
            )}
          </div>
        )}
        <div className="overflow-x-auto max-h-[600px]">
          <table className="w-full border-collapse">
            <thead>
              <tr>
                {showLineNumbers && <th className="w-16 px-3 py-2 text-left font-semibold text-foreground-secondary bg-background-tertiary border-b border-border">Line</th>}
                <th className="px-3 py-2 text-left font-semibold text-foreground-secondary bg-background-tertiary border-b border-border">Content</th>
              </tr>
            </thead>
            <tbody>
              {fixedLines.map((line, index) => {
                const lineNum = index + 1;
                const change = changeMap.get(lineNum);
                const isChange = !!change;

                if (!isChange) {
                  return (
                    <tr key={lineNum} className="line-unchanged">
                      {showLineNumbers && renderLineNumber(lineNum, '')}
                      <td className="px-3 py-1 whitespace-pre">{line || ' '}</td>
                    </tr>
                  );
                }

                if (change.type === 'added') {
                  return (
                    <tr key={lineNum} className="line-added">
                      {showLineNumbers && renderLineNumber(lineNum, 'text-accent-green')}
                      <td className="px-3 py-1 whitespace-pre">
                        <span className="inline-flex items-center gap-2">
                          <span className="text-accent-green">+</span>
                          {line}
                        </span>
                      </td>
                    </tr>
                  );
                }

                if (change.type === 'removed') {
                  return (
                    <tr key={lineNum} className="line-removed">
                      {showLineNumbers && renderLineNumber(lineNum, 'text-severity-critical')}
                      <td className="px-3 py-1 whitespace-pre">
                        <span className="inline-flex items-center gap-2">
                          <span className="text-severity-critical">-</span>
                          {change.originalContent}
                        </span>
                      </td>
                    </tr>
                  );
                }

                // Modified
                return (
                  <>
                    <tr key={`removed-${lineNum}`} className="line-removed">
                      {showLineNumbers && renderLineNumber(lineNum, 'text-severity-critical')}
                      <td className="px-3 py-1 whitespace-pre">
                        <span className="inline-flex items-center gap-2">
                          <span className="text-severity-critical">-</span>
                          {change.originalContent}
                        </span>
                      </td>
                    </tr>
                    <tr key={`added-${lineNum}`} className="line-added">
                      {showLineNumbers && renderLineNumber(0, 'text-accent-green')}
                      <td className="px-3 py-1 whitespace-pre">
                        <span className="inline-flex items-center gap-2">
                          <span className="text-accent-green">+</span>
                          {change.fixedContent}
                        </span>
                      </td>
                    </tr>
                  </>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    );
  }

  // Side-by-side view
  return (
    <div className="diff-view font-mono text-sm bg-background-tertiary border border-border rounded-lg overflow-hidden">
      {showActions && !readOnly && (
        <div className="flex items-center gap-2 p-3 border-b border-border bg-background-secondary">
          <div className="flex items-center gap-1 border border-border rounded px-2">
            <button
              className={clsx('px-2 py-1 text-xs rounded', !isUnified ? 'bg-accent-blue/20 text-accent-blue' : 'text-foreground-secondary hover:text-foreground')}
              onClick={() => setViewMode('side-by-side')}
            >
              Side by Side
            </button>
            <button
              className={clsx('px-2 py-1 text-xs rounded', isUnified ? 'bg-accent-blue/20 text-accent-blue' : 'text-foreground-secondary hover:text-foreground')}
              onClick={() => setViewMode('unified')}
            >
              Unified
            </button>
          </div>
          <label className="flex items-center gap-1 text-sm text-foreground-secondary">
            <input
              type="checkbox"
              checked={showLineNumbers}
              onChange={(e) => setShowLineNumbers(e.target.checked)}
              className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue"
            />
            Line numbers
          </label>
          <div className="flex-1" />
          {onApplyFixed && (
            <button className="btn-primary" onClick={onApplyFixed}>
              Apply Fixed Version
            </button>
          )}
          {onReset && (
            <button className="btn-secondary" onClick={onReset}>
              Reset
            </button>
          )}
        </div>
      )}
      <div className="flex overflow-x-auto max-h-[600px]">
        {/* Original */}
        <div className="w-1/2 border-r border-border min-w-0">
          <div className="sticky top-0 bg-background-secondary border-b border-border px-3 py-2 font-semibold text-foreground-secondary">
            Original
          </div>
          <div className="overflow-y-auto">
            <table className="w-full border-collapse">
              <tbody>
                {originalLines.map((line, index) => {
                  const lineNum = index + 1;
                  const change = changeMap.get(lineNum);
                  const lineClass = getLineClass(lineNum, true);
                  return (
                    <tr key={lineNum} className={lineClass}>
                      {showLineNumbers && renderLineNumber(lineNum, lineClass !== 'line-unchanged' ? 'text-severity-critical' : '')}
                      <td className="px-3 py-1 whitespace-pre">
                        {renderLineContent(line, change, true)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Fixed */}
        <div className="w-1/2 min-w-0">
          <div className="sticky top-0 bg-background-secondary border-b border-border px-3 py-2 font-semibold text-foreground-secondary">
            Fixed
          </div>
          <div className="overflow-y-auto">
            <table className="w-full border-collapse">
              <tbody>
                {fixedLines.map((line, index) => {
                  const lineNum = index + 1;
                  const change = changeMap.get(lineNum);
                  const lineClass = getLineClass(lineNum, false);
                  return (
                    <tr key={lineNum} className={lineClass}>
                      {showLineNumbers && renderLineNumber(lineNum, lineClass !== 'line-unchanged' ? 'text-accent-green' : '')}
                      <td className="px-3 py-1 whitespace-pre">
                        {renderLineContent(line, change, false)}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}