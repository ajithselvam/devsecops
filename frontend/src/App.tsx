import React, { Suspense, lazy } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { LoadingScreen } from './components/LoadingScreen';
import { useAuth } from './context/AuthContext';

// Lazy load page components
const Dashboard = lazy(() => import('./pages/Dashboard').then(m => ({ default: m.Dashboard })));
const DockerfileFixer = lazy(() => import('./pages/DockerfileFixer').then(m => ({ default: m.DockerfileFixer })));
const DockerScanner = lazy(() => import('./pages/DockerScanner').then(m => ({ default: m.DockerScanner })));
const KubernetesAssistant = lazy(() => import('./pages/KubernetesAssistant').then(m => ({ default: m.KubernetesAssistant })));
const JenkinsAssistant = lazy(() => import('./pages/JenkinsAssistant').then(m => ({ default: m.JenkinsAssistant })));
const GitHubSecurity = lazy(() => import('./pages/GitHubSecurity').then(m => ({ default: m.GitHubSecurity })));
const LogInvestigation = lazy(() => import('./pages/LogInvestigation').then(m => ({ default: m.LogInvestigation })));
const DependencyRadar = lazy(() => import('./pages/DependencyRadar').then(m => ({ default: m.DependencyRadar })));
const ScanHistory = lazy(() => import('./pages/ScanHistory').then(m => ({ default: m.ScanHistory })));
const Settings = lazy(() => import('./pages/Settings').then(m => ({ default: m.Settings })));
const Login = lazy(() => import('./pages/Login').then(m => ({ default: m.Login })));
const Register = lazy(() => import('./pages/Register').then(m => ({ default: m.Register })));

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return <LoadingScreen />;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
}

function PublicRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, loading } = useAuth();

  if (loading) {
    return <LoadingScreen />;
  }

  if (isAuthenticated) {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}

function App() {
  return (
    <Suspense fallback={<LoadingScreen />}>
      <Routes>
        <Route path="/login" element={<PublicRoute><Login /></PublicRoute>} />
        <Route path="/register" element={<PublicRoute><Register /></PublicRoute>} />
        <Route
          path="/*"
          element={
            <ProtectedRoute>
              <Layout />
            </ProtectedRoute>
          }
        >
          <Route index element={<Dashboard />} />
          <Route path="dockerfile" element={<DockerfileFixer />} />
          <Route path="docker" element={<DockerScanner />} />
          <Route path="kubernetes" element={<KubernetesAssistant />} />
          <Route path="jenkins" element={<JenkinsAssistant />} />
          <Route path="github" element={<GitHubSecurity />} />
          <Route path="logs" element={<LogInvestigation />} />
          <Route path="dependencies" element={<DependencyRadar />} />
          <Route path="scans" element={<ScanHistory />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </Suspense>
  );
}

export default App;