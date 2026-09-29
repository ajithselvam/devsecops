import { useRef, useCallback } from 'react';
import Editor from '@monaco-editor/react';
import { Copy, Download, Settings } from 'lucide-react';

interface CodeEditorProps {
  value: string;
  onChange: (value: string | undefined) => void;
  language?: string;
  theme?: 'vs-dark' | 'vs-light';
  readOnly?: boolean;
  maxHeight?: number;
  showLineNumbers?: boolean;
  showMinimap?: boolean;
  wordWrap?: 'on' | 'off' | 'bounded';
  tabSize?: number;
  placeholder?: string;
  onFormat?: () => void;
  fileName?: string;
}

const DEFAULT_LANGUAGES: Record<string, string> = {
  dockerfile: 'dockerfile',
  yaml: 'yaml',
  yml: 'yaml',
  json: 'json',
  groovy: 'groovy',
  jenkinsfile: 'groovy',
  javascript: 'javascript',
  typescript: 'typescript',
  python: 'python',
  go: 'go',
  rust: 'rust',
  bash: 'shell',
  sh: 'shell',
  sql: 'sql',
};

export function CodeEditor({
  value,
  onChange,
  language = 'plaintext',
  theme = 'vs-dark',
  readOnly = false,
  maxHeight = 600,
  showLineNumbers = true,
  showMinimap = false,
  wordWrap = 'on',
  tabSize = 2,
  placeholder,
  onFormat,
  fileName
}: CodeEditorProps) {
  const editorRef = useRef<any>(null);
  const mountedRef = useRef(false);

  const monacoLanguage = DEFAULT_LANGUAGES[language.toLowerCase()] || language;

  const handleEditorDidMount = useCallback((editor: any) => {
    editorRef.current = editor;
    mountedRef.current = true;

    // Set up format on save
    if (onFormat) {
      editor.addCommand(editor.KeyMod.CtrlCmd | editor.KeyCode.KeyS, () => {
        onFormat();
      });
    }

    // Auto-format on paste
    editor.onDidPaste(() => {
      setTimeout(() => {
        editor.getAction('editor.action.formatDocument')?.run();
      }, 0);
    });
  }, [onFormat]);

  const format = useCallback(() => {
    editorRef.current?.getAction('editor.action.formatDocument')?.run();
  }, []);

  const copyContent = useCallback(() => {
    navigator.clipboard.writeText(value);
  }, [value]);

  const downloadContent = useCallback(() => {
    const blob = new Blob([value], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileName || `code.${language}`;
    a.click();
    URL.revokeObjectURL(url);
  }, [value, language, fileName]);

  return (
    <div className="relative border border-border rounded-lg overflow-hidden bg-background-tertiary">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-3 py-2 bg-background-secondary border-b border-border">
        <span className="text-xs text-foreground-secondary font-medium uppercase tracking-wider">
          {fileName || monacoLanguage}
        </span>
        <div className="flex-1" />
        {!readOnly && (
          <>
            <button
              className="btn-icon p-1.5 text-foreground-secondary hover:text-foreground"
              onClick={format}
              aria-label="Format document"
              title="Format (Ctrl+S)"
            >
              <Settings className="w-4 h-4" />
            </button>
            <button
              className="btn-icon p-1.5 text-foreground-secondary hover:text-foreground"
              onClick={copyContent}
              aria-label="Copy to clipboard"
            >
              <Copy className="w-4 h-4" />
            </button>
            <button
              className="btn-icon p-1.5 text-foreground-secondary hover:text-foreground"
              onClick={downloadContent}
              aria-label="Download file"
            >
              <Download className="w-4 h-4" />
            </button>
          </>
        )}
        {readOnly && (
          <span className="badge badge-info">Read Only</span>
        )}
      </div>

      {/* Editor */}
      <Editor
        height={`${maxHeight}px`}
        defaultLanguage={monacoLanguage}
        defaultValue={value}
        onChange={onChange}
        onMount={handleEditorDidMount}
        options={{
          theme,
          readOnly,
          lineNumbers: showLineNumbers ? 'on' : 'off',
          minimap: { enabled: showMinimap },
          wordWrap,
          tabSize,
          fontSize: 13,
          fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
          fontLigatures: true,
          renderLineHighlight: 'all',
          scrollBeyondLastLine: false,
          automaticLayout: true,
          bracketPairColorization: { enabled: true },
          guides: { bracketPairs: true },
          folding: true,
          matchBrackets: 'always',
          renderWhitespace: 'selection',
          smoothScrolling: true,
          cursorBlinking: 'smooth',
          cursorSmoothCaretAnimation: 'on',
          scrollbar: {
            vertical: 'auto',
            horizontal: 'auto',
            useShadows: false,
            verticalHasArrows: false,
            horizontalHasArrows: false
          },
          find: { addExtraSpaceOnTop: false },
          placeholder: placeholder || '',
          ...(readOnly ? { contextmenu: false } : {})
        }}
      />

      {/* Status bar */}
      <div className="flex items-center gap-4 px-3 py-1.5 bg-background-secondary border-t border-border text-xs text-foreground-muted">
        <span>Ln {value.split('\n').length}, Col 1</span>
        <span>{monacoLanguage}</span>
        <span>Spaces: {tabSize}</span>
        <span>UTF-8</span>
      </div>
    </div>
  );
}