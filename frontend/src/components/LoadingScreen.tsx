import { Container, Zap } from 'lucide-react';

export function LoadingScreen() {
  return (
    <div className="min-h-screen bg-background flex items-center justify-center">
      <div className="text-center">
        <div className="relative w-24 h-24 mx-auto mb-6">
          <Container className="w-24 h-24 text-accent-blue animate-pulse-soft" />
          <Zap className="absolute top-2 right-2 w-8 h-8 text-accent-yellow animate-pulse" />
        </div>
        <h1 className="text-2xl font-bold text-foreground mb-2">DevSecOps AI Platform</h1>
        <p className="text-foreground-secondary">Loading your command center...</p>
        <div className="mt-8 w-64 mx-auto">
          <div className="progress-bar">
            <div className="progress-fill bg-accent-blue animate-pulse" style={{ width: '100%' }} />
          </div>
        </div>
      </div>
    </div>
  );
}

export function PageLoading() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="text-center">
        <div className="w-10 h-10 border-3 border-border border-t-accent-blue rounded-full animate-spin mx-auto mb-4" />
        <p className="text-foreground-secondary">Loading...</p>
      </div>
    </div>
  );
}

export function CardSkeleton() {
  return (
    <div className="card animate-pulse">
      <div className="skeleton-title" />
      <div className="space-y-3 mt-4">
        <div className="skeleton-text" />
        <div className="skeleton-text w-1/2" />
        <div className="skeleton-text w-3/4" />
      </div>
    </div>
  );
}

export function TableSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="table-container">
      <table className="table">
        <thead>
          <tr>
            <th><div className="skeleton-text w-24" /></th>
            <th><div className="skeleton-text w-20" /></th>
            <th><div className="skeleton-text w-28" /></th>
            <th><div className="skeleton-text w-16" /></th>
            <th><div className="skeleton-text w-20" /></th>
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: rows }).map((_, i) => (
            <tr key={i}>
              <td><div className="skeleton-text w-24" /></td>
              <td><div className="skeleton-text w-20" /></td>
              <td><div className="skeleton-text w-28" /></td>
              <td><div className="skeleton-text w-16" /></td>
              <td><div className="skeleton-text w-20" /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}