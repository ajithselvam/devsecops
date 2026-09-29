import { useState, useEffect, useCallback } from 'react';
import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import {
  LayoutDashboard,
  Container,
  ShieldCheck,
  Boxes,
  GitBranch,
  Github,
  FileSearch,
  Radar,
  History,
  Settings,
  Menu,
  X,
  Sun,
  Moon,
  ChevronDown,
  Cpu,
  CheckCircle,
  AlertCircle
} from 'lucide-react';
import { NotificationDropdown } from './NotificationDropdown';
import { UserMenu } from './UserMenu';
import { useWebSocket } from '../hooks/useWebSocket';
import { Notification } from '@devsecops/shared/types';
import { aiApi } from '../services/api';

const SIDEBAR_ITEMS = [
  { path: '/', label: 'Dashboard', icon: LayoutDashboard },
  { path: '/dockerfile', label: 'Dockerfile AI Fixer', icon: Container },
  { path: '/docker', label: 'Docker Image Scanner', icon: ShieldCheck },
  { path: '/kubernetes', label: 'Kubernetes YAML AI', icon: Boxes },
  { path: '/jenkins', label: 'Jenkins AI Assistant', icon: GitBranch },
  { path: '/github', label: 'GitHub Security', icon: Github },
  { path: '/logs', label: 'AI Log Investigation', icon: FileSearch },
  { path: '/dependencies', label: 'Dependency Risk Radar', icon: Radar },
  { path: '/scans', label: 'Scan History', icon: History },
  { path: '/settings', label: 'Settings', icon: Settings }
] as const;

export function Layout() {
  const { user, logout } = useAuth();
  const { resolvedTheme, toggleTheme } = useTheme();
  const navigate = useNavigate();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [aiConnected, setAiConnected] = useState<boolean | null>(null);
  const [aiChecking, setAiChecking] = useState(false);

  const { lastMessage: _lastMessage } = useWebSocket({
    onNotification: (notification: Notification) => {
      setNotifications(prev => [notification, ...prev].slice(0, 50));
      setUnreadCount(prev => prev + 1);
    },
    onJobUpdate: (_update) => {
      // Job updates handled by individual pages
    }
  });

  const checkAIConnection = useCallback(async () => {
    setAiChecking(true);
    try {
      const response = await aiApi.test();
      setAiConnected(response.data.success && response.data.data?.connected);
    } catch (err) {
      setAiConnected(false);
    } finally {
      setAiChecking(false);
    }
  }, []);

  useEffect(() => {
    // Load sidebar collapsed state
    const stored = localStorage.getItem('sidebarCollapsed');
    if (stored) setSidebarCollapsed(JSON.parse(stored));

    // Check AI connection on mount
    checkAIConnection();

    // Check AI connection every 30 seconds
    const interval = setInterval(checkAIConnection, 30000);
    return () => clearInterval(interval);
  }, [checkAIConnection]);

  useEffect(() => {
    localStorage.setItem('sidebarCollapsed', JSON.stringify(sidebarCollapsed));
  }, [sidebarCollapsed]);

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  return (
    <div className="min-h-screen bg-background flex">
      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
          aria-hidden="true"
        />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed lg:relative top-0 left-0 z-50 h-screen bg-background-secondary border-r border-border transition-all duration-300 flex flex-col ${
          sidebarCollapsed ? 'w-16' : 'w-64'
        } ${sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}`}
        aria-label="Main navigation"
      >
        {/* Logo / Brand */}
        <div className={`flex items-center justify-between h-16 px-4 border-b border-border ${sidebarCollapsed ? 'justify-center' : ''}`}>
          {!sidebarCollapsed && (
            <NavLink to="/" className="flex items-center gap-2 text-foreground font-semibold text-lg" aria-label="DevSecOps AI Platform">
              <Container className="w-6 h-6 text-accent-blue" />
              <span>DevSecOps AI</span>
            </NavLink>
          )}
          <button
            className="lg:hidden btn-icon text-foreground-secondary hover:text-foreground"
            onClick={() => setSidebarOpen(false)}
            aria-label="Close sidebar"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto p-3 space-y-1" role="navigation" aria-label="Main">
          {SIDEBAR_ITEMS.map((item) => {
            const Icon = item.icon;
            const isActive = window.location.pathname === item.path ||
              (item.path !== '/' && window.location.pathname.startsWith(item.path));
            return (
              <NavLink
                key={item.path}
                to={item.path}
                className={`sidebar-link ${isActive ? 'sidebar-link-active' : ''} ${sidebarCollapsed ? 'justify-center' : ''}`}
                aria-current={isActive ? 'page' : undefined}
                title={sidebarCollapsed ? item.label : undefined}
                onClick={() => setSidebarOpen(false)}
              >
                <Icon className="w-5 h-5 flex-shrink-0" aria-hidden="true" />
                {!sidebarCollapsed && <span>{item.label}</span>}
              </NavLink>
            );
          })}
        </nav>

        {/* AI Connection Status */}
        {!sidebarCollapsed && (
          <div className="px-3 py-2 border-t border-border">
            <div className="flex items-center gap-3 p-2 rounded-lg bg-background-tertiary/50">
              <Cpu className="w-5 h-5 text-foreground-muted flex-shrink-0" aria-hidden="true" />
              <div className="flex-1 min-w-0">
                <p className="text-xs font-medium text-foreground-secondary uppercase tracking-wider">AI Status</p>
                <div className="flex items-center gap-2 mt-0.5">
                  {aiChecking ? (
                    <div className="w-2 h-2 bg-accent-yellow rounded-full animate-pulse" />
                  ) : aiConnected === true ? (
                    <CheckCircle className="w-3.5 h-3.5 text-accent-green flex-shrink-0" />
                  ) : aiConnected === false ? (
                    <AlertCircle className="w-3.5 h-3.5 text-severity-critical flex-shrink-0" />
                  ) : (
                    <div className="w-2 h-2 bg-foreground-muted rounded-full" />
                  )}
                  <span className="text-xs text-foreground-secondary">
                    {aiChecking ? 'Checking...' : aiConnected === true ? 'Connected' : aiConnected === false ? 'Disconnected' : 'Unknown'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Sidebar toggle & user info */}
        <div className={`p-3 border-t border-border ${sidebarCollapsed ? 'items-center justify-center' : ''}`}>
          {!sidebarCollapsed && user && (
            <div className="flex items-center gap-3 p-2 rounded-lg hover:bg-background-tertiary">
              <div className="w-8 h-8 rounded-full bg-accent-blue/20 flex items-center justify-center">
                {user.avatarUrl ? (
                  <img src={user.avatarUrl} alt="" className="w-8 h-8 rounded-full" />
                ) : (
                  <span className="text-sm font-medium text-accent-blue">{user.name[0].toUpperCase()}</span>
                )}
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium text-foreground truncate">{user.name}</p>
                <p className="text-xs text-foreground-muted truncate">{user.email}</p>
              </div>
            </div>
          )}
          <button
            className={`btn-icon w-full ${sidebarCollapsed ? 'mx-auto' : ''}`}
            onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
            aria-expanded={!sidebarCollapsed}
          >
            {sidebarCollapsed ? (
              <ChevronDown className="w-5 h-5 rotate-180" />
            ) : (
              <Menu className="w-5 h-5" />
            )}
          </button>
        </div>
      </aside>

      {/* Main content */}
      <div className="flex-1 flex flex-col min-w-0 lg:ml-0">
        {/* Top Header */}
        <header className="sticky top-0 z-30 h-16 bg-background-secondary/80 backdrop-blur-lg border-b border-border flex items-center justify-between px-4 lg:px-6">
          <div className="flex items-center gap-4">
            <button
              className="lg:hidden btn-icon text-foreground-secondary hover:text-foreground"
              onClick={() => setSidebarOpen(true)}
              aria-label="Open sidebar"
            >
              <Menu className="w-5 h-5" />
            </button>
            <h1 className="text-lg font-semibold text-foreground hidden sm:block">
              {SIDEBAR_ITEMS.find(item =>
                window.location.pathname === item.path ||
                (item.path !== '/' && window.location.pathname.startsWith(item.path))
              )?.label || 'Dashboard'}
            </h1>
          </div>

          <div className="flex items-center gap-2">
            {/* Theme Toggle */}
            <button
              className="btn-icon text-foreground-secondary hover:text-foreground relative"
              onClick={toggleTheme}
              aria-label={`Switch to ${resolvedTheme === 'dark' ? 'light' : 'dark'} mode`}
            >
              {resolvedTheme === 'dark' ? (
                <Sun className="w-5 h-5" />
              ) : (
                <Moon className="w-5 h-5" />
              )}
            </button>

            {/* Notifications */}
            <NotificationDropdown
              notifications={notifications}
              unreadCount={unreadCount}
              onMarkRead={(id) => setNotifications(prev => prev.map(n => n.id === id ? { ...n, read: true } : n))}
              onMarkAllRead={() => setNotifications(prev => prev.map(n => ({ ...n, read: true })))}
            />

            {/* User Menu */}
            <UserMenu
              user={user}
              onLogout={handleLogout}
              onSettings={() => navigate('/settings')}
            />
          </div>
        </header>

        {/* Page Content */}
        <main className="flex-1 p-4 lg:p-6 overflow-auto">
          <Outlet />
        </main>
      </div>
    </div>
  );
}