import React, { useState, useCallback, useEffect } from 'react';
import {
  User,
  Shield,
  Key,
  Bell,
  Palette,
  Database,
  Server,
  Globe,
  Wrench,
  Download,
  Upload,
  Trash2,
  Eye,
  Save,
  Github,
  Gitlab,
  GitFork
} from 'lucide-react';
import { settingsApi } from '../services/api';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { toast } from 'react-hot-toast';
import { clsx } from 'clsx';

const TABS = [
  { id: 'general', label: 'General', icon: Wrench },
  { id: 'appearance', label: 'Appearance', icon: Palette },
  { id: 'notifications', label: 'Notifications', icon: Bell },
  { id: 'security', label: 'Security', icon: Shield },
  { id: 'integrations', label: 'Integrations', icon: Globe },
  { id: 'api', label: 'API Keys', icon: Key },
  { id: 'data', label: 'Data & Privacy', icon: Database },
  { id: 'advanced', label: 'Advanced', icon: Server }
];

export function Settings() {
  const { user, updateProfile, logout } = useAuth();
  const { theme: themeContext, setTheme: setThemeContext } = useTheme();
  const [activeTab, setActiveTab] = useState('general');
  const [saving, setSaving] = useState(false);
  const [loading, setLoading] = useState(true);

  // General settings
  const [displayName, setDisplayName] = useState('');
  const [email, setEmail] = useState('');
  const [timezone, setTimezone] = useState('UTC');
  const [language, setLanguage] = useState('en');

  // Appearance settings - sync with ThemeContext
  const [theme, setTheme] = useState<'dark' | 'light' | 'system'>(themeContext);
  const [compactMode, setCompactMode] = useState(false);
  const [animations, setAnimations] = useState(true);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  // Sync local theme state with ThemeContext when it changes
  useEffect(() => {
    setTheme(themeContext);
  }, [themeContext]);

  // Notification settings
  const [emailNotifications, setEmailNotifications] = useState(true);
  const [scanCompleteNotify, setScanCompleteNotify] = useState(true);
  const [scanFailedNotify, setScanFailedNotify] = useState(true);
  const [vulnerabilityAlerts, setVulnerabilityAlerts] = useState(true);
  const [weeklyDigest, setWeeklyDigest] = useState(false);

  // Security settings
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [twoFAEnabled, setTwoFAEnabled] = useState(false);
  const [sessionTimeout, setSessionTimeout] = useState(30);

  // Integration settings
  const [githubToken, setGithubToken] = useState('');
  const [gitlabToken, setGitlabToken] = useState('');
  const [bitbucketToken, setBitbucketToken] = useState('');
  const [slackWebhook, setSlackWebhook] = useState('');
  const [teamsWebhook, setTeamsWebhook] = useState('');
  const [jiraUrl, setJiraUrl] = useState('');
  const [jiraToken, setJiraToken] = useState('');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [webhookSecret, setWebhookSecret] = useState('');

  // API Keys
  const [apiKeys, setApiKeys] = useState<any[]>([]);
  const [newApiKeyName, setNewApiKeyName] = useState('');
  const [showApiKey, setShowApiKey] = useState<string | null>(null);
  const [creatingKey, setCreatingKey] = useState(false);

  // Advanced
  const [debugMode, setDebugMode] = useState(false);
  const [telemetryEnabled, setTelemetryEnabled] = useState(true);
  const [autoUpdate, setAutoUpdate] = useState(true);

  const loadSettings = useCallback(async () => {
    try {
      const response = await settingsApi.getAll();
      if (response.data.success) {
        saveSettings(response.data.data);
        // Apply settings to state
        if (response.data.data.general) {
          setDisplayName(response.data.data.general.displayName || '');
          setEmail(response.data.data.general.email || '');
          setTimezone(response.data.data.general.timezone || 'UTC');
          setLanguage(response.data.data.general.language || 'en');
        }
        if (response.data.data.appearance) {
          setTheme(response.data.data.appearance.theme || 'dark');
          setCompactMode(response.data.data.appearance.compactMode || false);
          setAnimations(response.data.data.appearance.animations !== false);
          setSidebarCollapsed(response.data.data.appearance.sidebarCollapsed || false);
        }
        if (response.data.data.notifications) {
          setEmailNotifications(response.data.data.notifications.email !== false);
          setScanCompleteNotify(response.data.data.notifications.scanComplete !== false);
          setScanFailedNotify(response.data.data.notifications.scanFailed !== false);
          setVulnerabilityAlerts(response.data.data.notifications.vulnerabilityAlerts !== false);
          setWeeklyDigest(response.data.data.notifications.weeklyDigest || false);
        }
        if (response.data.data.security) {
          setTwoFAEnabled(response.data.data.security.twoFA || false);
          setSessionTimeout(response.data.data.security.sessionTimeout || 30);
        }
        if (response.data.data.integrations) {
          setGithubToken(response.data.data.integrations.github?.token || '');
          setGitlabToken(response.data.data.integrations.gitlab?.token || '');
          setBitbucketToken(response.data.data.integrations.bitbucket?.token || '');
          setSlackWebhook(response.data.data.integrations.slack?.webhook || '');
          setTeamsWebhook(response.data.data.integrations.teams?.webhook || '');
          setJiraUrl(response.data.data.integrations.jira?.url || '');
          setJiraToken(response.data.data.integrations.jira?.token || '');
          setWebhookUrl(response.data.data.integrations.webhook?.url || '');
          setWebhookSecret(response.data.data.integrations.webhook?.secret || '');
        }
        if (response.data.data.apiKeys) {
          setApiKeys(response.data.data.apiKeys);
        }
        if (response.data.data.advanced) {
          setDebugMode(response.data.data.advanced.debugMode || false);
          setTelemetryEnabled(response.data.data.advanced.telemetry !== false);
          setAutoUpdate(response.data.data.advanced.autoUpdate !== false);
        }
      }
    } catch (err) {
      toast.error('Failed to load settings');
      console.error(err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadSettings();
  }, [loadSettings]);

  const saveSettings = async (tab: string) => {
    setSaving(true);
    try {
      let data: any = {};
      switch (tab) {
        case 'general':
          data = { general: { displayName, email, timezone, language } };
          break;
        case 'appearance':
          data = { appearance: { theme, compactMode, animations, sidebarCollapsed } };
          break;
        case 'notifications':
          data = { notifications: { email: emailNotifications, scanComplete: scanCompleteNotify, scanFailed: scanFailedNotify, vulnerabilityAlerts, weeklyDigest } };
          break;
        case 'security':
          if (newPassword && newPassword !== confirmPassword) {
            toast.error('Passwords do not match');
            setSaving(false);
            return;
          }
          data = { security: { currentPassword, newPassword, twoFA: twoFAEnabled, sessionTimeout } };
          break;
        case 'integrations':
          data = { integrations: { github: githubToken ? { token: githubToken } : undefined, gitlab: gitlabToken ? { token: gitlabToken } : undefined, bitbucket: bitbucketToken ? { token: bitbucketToken } : undefined, slack: slackWebhook ? { webhook: slackWebhook } : undefined, teams: teamsWebhook ? { webhook: teamsWebhook } : undefined, jira: jiraUrl ? { url: jiraUrl, token: jiraToken } : undefined, webhook: webhookUrl ? { url: webhookUrl, secret: webhookSecret } : undefined } };
          break;
        case 'advanced':
          data = { advanced: { debugMode, telemetryEnabled, autoUpdate } };
          break;
      }
      const response = await settingsApi.update(data);
      if (response.data.success) {
        toast.success('Settings saved');
        if (tab === 'general' && displayName !== user?.name) {
          updateProfile({ name: displayName, email });
        }
        if (tab === 'appearance') {
          // Apply theme immediately via ThemeContext
          setThemeContext(theme);
        }
      } else {
        toast.error(response.data.error?.message || 'Save failed');
      }
    } catch (err) {
      toast.error('Failed to save settings');
      console.error(err);
    } finally {
      setSaving(false);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    }
  };

  const createApiKey = async () => {
    if (!newApiKeyName.trim()) {
      toast.error('Enter a name for the API key');
      return;
    }
    setCreatingKey(true);
    try {
      const response = await settingsApi.createApiKey({ name: newApiKeyName.trim() });
      if (response.data.success) {
        setShowApiKey(response.data.data.key);
        setApiKeys(prev => [response.data.data, ...prev]);
        setNewApiKeyName('');
        toast.success('API key created! Copy it now - you won\'t see it again.');
      } else {
        toast.error(response.data.error?.message || 'Creation failed');
      }
    } catch (err) {
      toast.error('Failed to create API key');
      console.error(err);
    } finally {
      setCreatingKey(false);
    }
  };

  const revokeApiKey = async (id: string) => {
    try {
      const response = await settingsApi.revokeApiKey(id);
      if (response.data.success) {
        setApiKeys(prev => prev.filter(k => k.id !== id));
        toast.success('API key revoked');
      } else {
        toast.error(response.data.error?.message || 'Revoke failed');
      }
    } catch (err) {
      toast.error('Failed to revoke');
      console.error(err);
    }
  };

  const exportData = async () => {
    try {
      const response = await settingsApi.exportData();
      if (response.data.success) {
        const blob = new Blob([JSON.stringify(response.data.data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `devsecops-export-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
        toast.success('Data exported');
      }
    } catch (err) {
      toast.error('Export failed');
      console.error(err);
    }
  };

  const handleImport = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
      const response = await settingsApi.importData(file);
      if (response.data.success) {
        toast.success('Data imported successfully');
        loadSettings();
      } else {
        toast.error(response.data.error?.message || 'Import failed');
      }
    } catch (err) {
      toast.error('Import failed');
      console.error(err);
    }
    event.target.value = '';
  };

  const deleteAccount = async () => {
    if (!window.confirm('This will permanently delete your account and all data. This cannot be undone. Continue?')) return;
    if (!window.confirm('Are you absolutely sure? Type "DELETE" to confirm.')) return;
    try {
      const response = await settingsApi.deleteAccount();
      if (response.data.success) {
        toast.success('Account deleted');
        logout();
      } else {
        toast.error(response.data.error?.message || 'Deletion failed');
      }
    } catch (err) {
      toast.error('Failed to delete account');
      console.error(err);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="w-8 h-8 border-2 border-accent-blue/30 border-t-accent-blue rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Settings</h1>
          <p className="text-foreground-secondary mt-1">
            Manage your account, preferences, and integrations
          </p>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="tabs flex-wrap">
        {TABS.map(tab => (
          <button
            key={tab.id}
            className={clsx('tab', activeTab === tab.id && 'tab-active')}
            onClick={() => setActiveTab(tab.id)}
          >
            {React.createElement(tab.icon, { className: 'w-4 h-4' })}
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="card">
        {activeTab === 'general' && (
          <div className="space-y-6 max-w-2xl">
            <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
              <User className="w-5 h-5 text-accent-blue" />
              Profile
            </h3>
            <div className="space-y-4">
              <div>
                <label className="label">Display Name</label>
                <input
                  type="text"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  className="input"
                  placeholder="Your name"
                />
              </div>
              <div>
                <label className="label">Email Address</label>
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="input"
                  placeholder="you@example.com"
                />
              </div>
              <div>
                <label className="label">Timezone</label>
                <select value={timezone} onChange={(e) => setTimezone(e.target.value)} className="input">
                  <option value="UTC">UTC</option>
                  <option value="America/New_York">Eastern Time</option>
                  <option value="America/Chicago">Central Time</option>
                  <option value="America/Denver">Mountain Time</option>
                  <option value="America/Los_Angeles">Pacific Time</option>
                  <option value="Europe/London">London</option>
                  <option value="Europe/Paris">Paris</option>
                  <option value="Asia/Tokyo">Tokyo</option>
                  <option value="Asia/Shanghai">Shanghai</option>
                  <option value="Australia/Sydney">Sydney</option>
                </select>
              </div>
              <div>
                <label className="label">Language</label>
                <select value={language} onChange={(e) => setLanguage(e.target.value)} className="input">
                  <option value="en">English</option>
                  <option value="es">Spanish</option>
                  <option value="fr">French</option>
                  <option value="de">German</option>
                  <option value="ja">Japanese</option>
                  <option value="zh">Chinese</option>
                </select>
              </div>
            </div>
            <button className="btn-primary" onClick={() => saveSettings('general')} disabled={saving}>
              {saving ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Save className="w-4 h-4" />}
              Save Changes
            </button>
          </div>
        )}

        {activeTab === 'appearance' && (
          <div className="space-y-6 max-w-2xl">
            <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
              <Palette className="w-5 h-5 text-accent-purple" />
              Appearance
            </h3>
            <div className="space-y-4">
              <div>
                <label className="label">Theme</label>
                <div className="grid grid-cols-3 gap-2">
                  {(['dark', 'light', 'system'] as const).map(t => (
                    <button
                      key={t}
                      className={clsx(
                        'p-4 rounded-lg border-2 text-center transition-colors',
                        theme === t ? 'border-accent-blue bg-accent-blue/10' : 'border-border hover:border-accent-blue/50'
                      )}
                      onClick={() => setTheme(t)}
                    >
                      <div className="text-2xl mb-1">{t === 'dark' ? '🌙' : t === 'light' ? '☀️' : '💻'}</div>
                      <p className="font-medium capitalize">{t}</p>
                    </button>
                  ))}
                </div>
              </div>
              <div className="space-y-3 border-t border-border pt-4">
                <label className="flex items-center justify-between cursor-pointer">
                  <div>
                    <p className="font-medium text-foreground">Compact Mode</p>
                    <p className="text-sm text-foreground-muted">Reduce padding and spacing</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={compactMode}
                    onChange={(e) => setCompactMode(e.target.checked)}
                    className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue w-5 h-5"
                  />
                </label>
                <label className="flex items-center justify-between cursor-pointer">
                  <div>
                    <p className="font-medium text-foreground">Animations</p>
                    <p className="text-sm text-foreground-muted">Enable UI animations and transitions</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={animations}
                    onChange={(e) => setAnimations(e.target.checked)}
                    className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue w-5 h-5"
                  />
                </label>
                <label className="flex items-center justify-between cursor-pointer">
                  <div>
                    <p className="font-medium text-foreground">Sidebar Collapsed</p>
                    <p className="text-sm text-foreground-muted">Start with sidebar minimized</p>
                  </div>
                  <input
                    type="checkbox"
                    checked={sidebarCollapsed}
                    onChange={(e) => setSidebarCollapsed(e.target.checked)}
                    className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue w-5 h-5"
                  />
                </label>
              </div>
            </div>
            <button className="btn-primary" onClick={() => saveSettings('appearance')} disabled={saving}>
              {saving ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Save className="w-4 h-4" />}
              Save Changes
            </button>
          </div>
        )}

        {activeTab === 'notifications' && (
          <div className="space-y-6 max-w-2xl">
            <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
              <Bell className="w-5 h-5 text-accent-yellow" />
              Notifications
            </h3>
            <div className="space-y-4">
              <label className="flex items-center justify-between cursor-pointer">
                <div>
                  <p className="font-medium text-foreground">Email Notifications</p>
                  <p className="text-sm text-foreground-muted">Receive email notifications</p>
                </div>
                <input
                  type="checkbox"
                  checked={emailNotifications}
                  onChange={(e) => setEmailNotifications(e.target.checked)}
                  className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue w-5 h-5"
                />
              </label>
              <label className="flex items-center justify-between cursor-pointer">
                <div>
                  <p className="font-medium text-foreground">Scan Completion</p>
                  <p className="text-sm text-foreground-muted">Notify when scans complete successfully</p>
                </div>
                <input
                  type="checkbox"
                  checked={scanCompleteNotify}
                  onChange={(e) => setScanCompleteNotify(e.target.checked)}
                  className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue w-5 h-5"
                />
              </label>
              <label className="flex items-center justify-between cursor-pointer">
                <div>
                  <p className="font-medium text-foreground">Scan Failures</p>
                  <p className="text-sm text-foreground-muted">Notify when scans fail</p>
                </div>
                <input
                  type="checkbox"
                  checked={scanFailedNotify}
                  onChange={(e) => setScanFailedNotify(e.target.checked)}
                  className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue w-5 h-5"
                />
              </label>
              <label className="flex items-center justify-between cursor-pointer">
                <div>
                  <p className="font-medium text-foreground">Vulnerability Alerts</p>
                  <p className="text-sm text-foreground-muted">Alert on critical/high vulnerabilities</p>
                </div>
                <input
                  type="checkbox"
                  checked={vulnerabilityAlerts}
                  onChange={(e) => setVulnerabilityAlerts(e.target.checked)}
                  className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue w-5 h-5"
                />
              </label>
              <label className="flex items-center justify-between cursor-pointer">
                <div>
                  <p className="font-medium text-foreground">Weekly Digest</p>
                  <p className="text-sm text-foreground-muted">Receive weekly security summary</p>
                </div>
                <input
                  type="checkbox"
                  checked={weeklyDigest}
                  onChange={(e) => setWeeklyDigest(e.target.checked)}
                  className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue w-5 h-5"
                />
              </label>
            </div>
            <button className="btn-primary" onClick={() => saveSettings('notifications')} disabled={saving}>
              {saving ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Save className="w-4 h-4" />}
              Save Changes
            </button>
          </div>
        )}

        {activeTab === 'security' && (
          <div className="space-y-6 max-w-2xl">
            <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
              <Shield className="w-5 h-5 text-accent-green" />
              Security
            </h3>

            <div className="border-t border-border pt-6">
              <h4 className="font-medium text-foreground mb-4">Change Password</h4>
              <div className="space-y-4">
                <div>
                  <label className="label">Current Password</label>
                  <div className="relative">
                    <input
                      type="password"
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                      className="input"
                      placeholder="Enter current password"
                    />
                  </div>
                </div>
                <div>
                  <label className="label">New Password</label>
                  <div className="relative">
                    <input
                      type="password"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      className="input"
                      placeholder="Enter new password"
                    />
                  </div>
                  <p className="text-xs text-foreground-muted mt-1">Minimum 8 characters</p>
                </div>
                <div>
                  <label className="label">Confirm New Password</label>
                  <div className="relative">
                    <input
                      type="password"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      className="input"
                      placeholder="Confirm new password"
                    />
                  </div>
                </div>
              </div>
            </div>

            <div className="border-t border-border pt-6">
              <h4 className="font-medium text-foreground mb-4">Two-Factor Authentication</h4>
              <label className="flex items-center justify-between cursor-pointer">
                <div>
                  <p className="font-medium text-foreground">Enable 2FA</p>
                  <p className="text-sm text-foreground-muted">Add an extra layer of security (TOTP)</p>
                </div>
                <input
                  type="checkbox"
                  checked={twoFAEnabled}
                  onChange={(e) => setTwoFAEnabled(e.target.checked)}
                  className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue w-5 h-5"
                />
              </label>
              {twoFAEnabled && (
                <div className="mt-3 p-3 bg-accent-green/10 border border-accent-green/20 rounded-lg text-sm text-accent-green">
                  2FA is enabled. <a href="#" className="underline">Manage backup codes</a>
                </div>
              )}
            </div>

            <div className="border-t border-border pt-6">
              <h4 className="font-medium text-foreground mb-4">Session</h4>
              <div>
                <label className="label">Session Timeout (minutes)</label>
                <input
                  type="number"
                  value={sessionTimeout}
                  onChange={(e) => setSessionTimeout(parseInt(e.target.value) || 30)}
                  className="input w-32"
                  min={5}
                  max={480}
                />
              </div>
            </div>

            <button className="btn-primary" onClick={() => saveSettings('security')} disabled={saving}>
              {saving ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Save className="w-4 h-4" />}
              Save Changes
            </button>
          </div>
        )}

        {activeTab === 'integrations' && (
          <div className="space-y-6 max-w-2xl">
            <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
              <Globe className="w-5 h-5 text-accent-blue" />
              Integrations
            </h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 bg-background-tertiary rounded-lg">
                <div className="flex items-center gap-3 mb-3">
                  <Github className="w-5 h-5 text-foreground" />
                  <h4 className="font-medium text-foreground">GitHub</h4>
                </div>
                <input
                  type="password"
                  value={githubToken}
                  onChange={(e) => setGithubToken(e.target.value)}
                  placeholder="ghp_..."
                  className="input"
                />
                <p className="text-xs text-foreground-muted mt-1">Personal Access Token with repo scope</p>
              </div>
              <div className="p-4 bg-background-tertiary rounded-lg">
                <div className="flex items-center gap-3 mb-3">
                  <Gitlab className="w-5 h-5 text-foreground" />
                  <h4 className="font-medium text-foreground">GitLab</h4>
                </div>
                <input
                  type="password"
                  value={gitlabToken}
                  onChange={(e) => setGitlabToken(e.target.value)}
                  placeholder="glpat-..."
                  className="input"
                />
              </div>
              <div className="p-4 bg-background-tertiary rounded-lg">
                <div className="flex items-center gap-3 mb-3">
                  <GitFork className="w-5 h-5 text-foreground" />
                  <h4 className="font-medium text-foreground">Bitbucket</h4>
                </div>
                <input
                  type="password"
                  value={bitbucketToken}
                  onChange={(e) => setBitbucketToken(e.target.value)}
                  placeholder="App password"
                  className="input"
                />
              </div>
              <div className="p-4 bg-background-tertiary rounded-lg">
                <h4 className="font-medium text-foreground mb-3">Slack</h4>
                <input
                  type="text"
                  value={slackWebhook}
                  onChange={(e) => setSlackWebhook(e.target.value)}
                  placeholder="https://hooks.slack.com/services/..."
                  className="input"
                />
              </div>
              <div className="p-4 bg-background-tertiary rounded-lg">
                <h4 className="font-medium text-foreground mb-3">Microsoft Teams</h4>
                <input
                  type="text"
                  value={teamsWebhook}
                  onChange={(e) => setTeamsWebhook(e.target.value)}
                  placeholder="Webhook URL"
                  className="input"
                />
              </div>
              <div className="p-4 bg-background-tertiary rounded-lg">
                <h4 className="font-medium text-foreground mb-3">Jira</h4>
                <input
                  type="text"
                  value={jiraUrl}
                  onChange={(e) => setJiraUrl(e.target.value)}
                  placeholder="https://your-domain.atlassian.net"
                  className="input mb-2"
                />
                <input
                  type="password"
                  value={jiraToken}
                  onChange={(e) => setJiraToken(e.target.value)}
                  placeholder="API Token"
                  className="input"
                />
              </div>
              <div className="p-4 bg-background-tertiary rounded-lg">
                <h4 className="font-medium text-foreground mb-3">Custom Webhook</h4>
                <input
                  type="text"
                  value={webhookUrl}
                  onChange={(e) => setWebhookUrl(e.target.value)}
                  placeholder="https://your-webhook-url.com"
                  className="input mb-2"
                />
                <input
                  type="password"
                  value={webhookSecret}
                  onChange={(e) => setWebhookSecret(e.target.value)}
                  placeholder="Secret for HMAC verification"
                  className="input"
                />
              </div>
            </div>

            <button className="btn-primary" onClick={() => saveSettings('integrations')} disabled={saving}>
              {saving ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Save className="w-4 h-4" />}
              Save Changes
            </button>
          </div>
        )}

        {activeTab === 'api' && (
          <div className="max-w-2xl">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
                <Key className="w-5 h-5 text-accent-yellow" />
                API Keys
              </h3>
              <button className="btn-primary" onClick={() => setShowApiKey('new')} disabled={creatingKey}>
                {creatingKey ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <>+ New Key</>}
              </button>
            </div>

            {showApiKey === 'new' && (
              <div className="mb-4 p-4 bg-background-tertiary rounded-lg">
                <h4 className="font-medium text-foreground mb-3">Create New API Key</h4>
                <div className="flex gap-2 mb-3">
                  <input
                    type="text"
                    value={newApiKeyName}
                    onChange={(e) => setNewApiKeyName(e.target.value)}
                    placeholder="Key name (e.g., CI/CD Pipeline)"
                    className="input flex-1"
                  />
                  <button className="btn-primary" onClick={createApiKey} disabled={creatingKey}>
                    Create
                  </button>
                </div>
                <button className="btn-secondary text-sm" onClick={() => setShowApiKey(null)}>
                  Cancel
                </button>
              </div>
            )}

            {showApiKey && showApiKey !== 'new' && (
              <div className="modal-overlay" onClick={() => setShowApiKey(null)}>
                <div className="modal-content w-full max-w-md p-6" onClick={(e) => e.stopPropagation()}>
                  <h4 className="font-medium text-foreground mb-3">API Key Created</h4>
                  <div className="code-block mb-4">
                    <code className="text-sm">{showApiKey}</code>
                  </div>
                  <p className="text-sm text-foreground-muted mb-4">
                    Copy this key now. You won't be able to see it again.
                  </p>
                  <button className="btn-primary w-full" onClick={() => { navigator.clipboard.writeText(showApiKey); toast.success('Copied!'); setShowApiKey(null); }}>
                    Copy & Close
                  </button>
                </div>
              </div>
            )}

            {apiKeys.length === 0 ? (
              <div className="text-center py-12">
                <Key className="w-12 h-12 mx-auto text-foreground-muted mb-4" />
                <p className="text-foreground-secondary">No API keys created yet</p>
                <p className="text-sm text-foreground-muted mt-1">Create a key to access the API programmatically</p>
              </div>
            ) : (
              <div className="space-y-3">
                {apiKeys.map(key => (
                  <div key={key.id} className="p-4 bg-background-tertiary rounded-lg flex items-center justify-between">
                    <div>
                      <p className="font-medium text-foreground">{key.name}</p>
                      <p className="text-sm text-foreground-muted">Created: {new Date(key.createdAt).toLocaleDateString()} • Last used: {key.lastUsed ? new Date(key.lastUsed).toLocaleDateString() : 'Never'}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        className="btn-icon"
                        onClick={() => { setShowApiKey(key.keyPreview || 'hidden'); }}
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                      <button
                        className="btn-icon text-severity-critical hover:text-severity-critical/80"
                        onClick={() => revokeApiKey(key.id)}
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {activeTab === 'data' && (
          <div className="space-y-6 max-w-2xl">
            <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
              <Database className="w-5 h-5 text-accent-blue" />
              Data & Privacy
            </h3>

            <div className="border-t border-border pt-6">
              <h4 className="font-medium text-foreground mb-4">Export Data</h4>
              <p className="text-sm text-foreground-secondary mb-4">Download all your scans, settings, and configuration as JSON.</p>
              <button className="btn-secondary" onClick={exportData}>
                <Download className="w-4 h-4" />
                Export My Data
              </button>
            </div>

            <div className="border-t border-border pt-6">
              <h4 className="font-medium text-foreground mb-4">Import Data</h4>
              <p className="text-sm text-foreground-secondary mb-4">Import previously exported data (scans, settings, etc.).</p>
              <div className="relative">
                <input
                  type="file"
                  accept=".json"
                  onChange={handleImport}
                  className="hidden"
                  id="import-file"
                />
                <label htmlFor="import-file" className="btn-secondary cursor-pointer">
                  <Upload className="w-4 h-4" />
                  Choose File
                </label>
              </div>
            </div>

            <div className="border-t border-border pt-6">
              <h4 className="font-medium text-foreground mb-4 text-severity-critical">Danger Zone</h4>
              <div className="p-4 bg-severity-critical/10 border border-severity-critical/20 rounded-lg">
                <p className="text-sm text-severity-critical mb-3">Delete Account</p>
                <p className="text-sm text-foreground-secondary mb-4">Permanently delete your account and all associated data. This action cannot be undone.</p>
                <button className="btn-destructive" onClick={deleteAccount}>
                  <Trash2 className="w-4 h-4" />
                  Delete My Account
                </button>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'advanced' && (
          <div className="space-y-6 max-w-2xl">
            <h3 className="text-lg font-semibold text-foreground flex items-center gap-2">
              <Server className="w-5 h-5 text-accent-purple" />
              Advanced
            </h3>

            <div className="space-y-4">
              <label className="flex items-center justify-between cursor-pointer">
                <div>
                  <p className="font-medium text-foreground">Debug Mode</p>
                  <p className="text-sm text-foreground-muted">Enable verbose logging and debug features</p>
                </div>
                <input
                  type="checkbox"
                  checked={debugMode}
                  onChange={(e) => setDebugMode(e.target.checked)}
                  className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue w-5 h-5"
                />
              </label>
              <label className="flex items-center justify-between cursor-pointer">
                <div>
                  <p className="font-medium text-foreground">Telemetry</p>
                  <p className="text-sm text-foreground-muted">Send anonymous usage data to improve the product</p>
                </div>
                <input
                  type="checkbox"
                  checked={telemetryEnabled}
                  onChange={(e) => setTelemetryEnabled(e.target.checked)}
                  className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue w-5 h-5"
                />
              </label>
              <label className="flex items-center justify-between cursor-pointer">
                <div>
                  <p className="font-medium text-foreground">Auto Update</p>
                  <p className="text-sm text-foreground-muted">Automatically check for and apply updates</p>
                </div>
                <input
                  type="checkbox"
                  checked={autoUpdate}
                  onChange={(e) => setAutoUpdate(e.target.checked)}
                  className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue w-5 h-5"
                />
              </label>
            </div>

            <div className="border-t border-border pt-6">
              <h4 className="font-medium text-foreground mb-4">System Info</h4>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div className="p-3 bg-background-tertiary rounded-lg">
                  <p className="text-foreground-secondary">Version</p>
                  <p className="font-mono text-foreground">1.0.0</p>
                </div>
                <div className="p-3 bg-background-tertiary rounded-lg">
                  <p className="text-foreground-secondary">Build</p>
                  <p className="font-mono text-foreground">26-aug-2026</p>
                </div>
                <div className="p-3 bg-background-tertiary rounded-lg">
                  <p className="text-foreground-secondary">Node</p>
                  <p className="font-mono text-foreground">20.x</p>
                </div>
                <div className="p-3 bg-background-tertiary rounded-lg">
                  <p className="text-foreground-secondary">Database</p>
                  <p className="font-mono text-foreground">SQLite</p>
                </div>
              </div>
            </div>

            <button className="btn-primary" onClick={() => saveSettings('advanced')} disabled={saving}>
              {saving ? <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Save className="w-4 h-4" />}
              Save Changes
            </button>
          </div>
        )}
      </div>
    </div>
  );
}