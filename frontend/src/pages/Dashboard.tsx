import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Container,
  ShieldCheck,
  Boxes,
  GitBranch,
  Github,
  FileSearch,
  Radar,
  History,
  AlertTriangle,
  CheckCircle,
  TrendingUp,
  TrendingDown,
  Clock,
  Zap,
  ExternalLink,
  RefreshCw
} from 'lucide-react';
import { scansApi, jobsApi } from '../services/api';
import { Scan, Job } from '@devsecops/shared/types';
import { CardSkeleton } from '../components/LoadingScreen';
import { formatDistanceToNow } from 'date-fns';
import { clsx } from 'clsx';

const QUICK_ACTIONS = [
  { path: '/dockerfile', label: 'Analyze Dockerfile', description: 'Scan & fix Dockerfile issues', icon: Container, color: 'text-accent-blue' },
  { path: '/docker', label: 'Scan Docker Image', description: 'Find vulnerabilities in images', icon: ShieldCheck, color: 'text-accent-green' },
  { path: '/kubernetes', label: 'Kubernetes YAML', description: 'Validate & generate K8s configs', icon: Boxes, color: 'text-accent-purple' },
  { path: '/jenkins', label: 'Jenkins Pipeline', description: 'Fix & generate Jenkinsfiles', icon: GitBranch, color: 'text-accent-yellow' },
  { path: '/github', label: 'GitHub Security', description: 'Scan repos for vulnerabilities', icon: Github, color: 'text-foreground' },
  { path: '/logs', label: 'Investigate Logs', description: 'AI-powered log analysis', icon: FileSearch, color: 'text-accent-cyan' },
  { path: '/dependencies', label: 'Dependency Risk', description: 'Scan & fix vulnerable deps', icon: Radar, color: 'text-accent-purple' },
  { path: '/scans', label: 'Scan History', description: 'View all past scans', icon: History, color: 'text-foreground-muted' },
];

const STATS = [
  { label: 'Total Scans', value: '0', change: '+12%', trend: 'up', icon: CheckCircle, color: 'text-accent-green' },
  { label: 'Vulnerabilities Found', value: '0', change: '+5%', trend: 'up', icon: AlertTriangle, color: 'text-severity-critical' },
  { label: 'Critical Issues', value: '0', change: '-3%', trend: 'down', icon: AlertTriangle, color: 'text-severity-critical' },
  { label: 'Issues Fixed', value: '0', change: '+8%', trend: 'up', icon: Zap, color: 'text-accent-blue' },
];

export function Dashboard() {
  const [stats, setStats] = useState(STATS);
  const [recentScans, setRecentScans] = useState<Scan[]>([]);
  const [recentJobs, setRecentJobs] = useState<Job[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadDashboardData();
  }, []);

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      const [scansRes, jobsRes] = await Promise.all([
        scansApi.list({ page: 1, pageSize: 10 }),
        jobsApi.list({ page: 1, pageSize: 10 })
      ]);

      if (scansRes.data.success) {
        setRecentScans(scansRes.data.data?.data || []);
        // Update stats based on actual data
        const allScans = scansRes.data.data?.data || [];
        setStats([
          { ...STATS[0], value: allScans.length.toString() },
          {
            ...STATS[1],
            value: allScans.reduce((sum: number, s: Scan) => sum + (s.summary?.totalFindings || 0), 0).toString()
          },
          {
            ...STATS[2],
            value: allScans.reduce((sum: number, s: Scan) => sum + (s.summary?.critical || 0), 0).toString()
          },
          {
            ...STATS[3],
            value: allScans.reduce((sum: number, s: Scan) => sum + (s.summary?.fixedCount || 0), 0).toString()
          }
        ]);
      }

      if (jobsRes.data.success) {
        setRecentJobs(jobsRes.data.data?.data || []);
      }
    } catch (err) {
      console.error('Failed to load dashboard data', err);
    } finally {
      setLoading(false);
    }
  };

  const getStatusColor = (status: Job['status']) => {
    switch (status) {
      case 'completed': return 'text-accent-green';
      case 'failed': return 'text-severity-critical';
      case 'running':
      case 'analyzing':
      case 'fixing': return 'text-accent-blue';
      case 'queued': return 'text-foreground-muted';
      default: return 'text-foreground-secondary';
    }
  };

  const getStatusIcon = (status: Job['status']) => {
    switch (status) {
      case 'completed': return <CheckCircle className="w-4 h-4" />;
      case 'failed': return <AlertTriangle className="w-4 h-4" />;
      case 'running':
      case 'analyzing':
      case 'fixing': return <RefreshCw className="w-4 h-4 animate-spin" />;
      case 'queued': return <Clock className="w-4 h-4" />;
      default: return <Clock className="w-4 h-4" />;
    }
  };

  if (loading) {
    return (
      <div className="space-y-6 animate-fade-in">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map(i => <CardSkeleton key={i} />)}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <CardSkeleton />
          <CardSkeleton />
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Dashboard</h1>
          <p className="text-foreground-secondary mt-1">Your DevSecOps command center overview</p>
        </div>
        <button className="btn-secondary" onClick={loadDashboardData}>
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {stats.map((stat, index) => (
          <div key={index} className="stat-card">
            <div className="flex items-start justify-between">
              <div>
                <p className="stat-label">{stat.label}</p>
                <p className="stat-value">{stat.value}</p>
                <div className="stat-trend">
                  {stat.trend === 'up' ? (
                    <TrendingUp className="w-4 h-4 text-accent-green" />
                  ) : (
                    <TrendingDown className="w-4 h-4 text-severity-critical" />
                  )}
                  <span className={clsx('font-medium', stat.color)}>{stat.change}</span>
                </div>
              </div>
              <div className={`p-3 rounded-xl bg-background-tertiary ${stat.color.replace('text-', 'bg-')}/10`}>
                <stat.icon className={`w-6 h-6 ${stat.color}`} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column - Quick Actions & Recent Scans */}
        <div className="lg:col-span-2 space-y-6">
          {/* Quick Actions */}
          <div className="card">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-foreground">Quick Actions</h2>
              <Link to="/scans" className="text-sm text-accent-blue hover:underline">View all</Link>
            </div>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {QUICK_ACTIONS.map((action, i) => {
                const Icon = action.icon;
                return (
                  <Link
                    key={i}
                    to={action.path}
                    className="card p-4 hover:shadow-card-hover transition-shadow group"
                  >
                    <div className={`p-2 rounded-lg bg-background-tertiary ${action.color} mb-3`}>
                      <Icon className="w-5 h-5" />
                    </div>
                    <h3 className="font-medium text-foreground">{action.label}</h3>
                    <p className="text-sm text-foreground-secondary mt-1">{action.description}</p>
                    <div className="mt-3 flex items-center text-accent-blue text-sm group-hover:gap-1 transition-all">
                      <span>Open</span>
                      <ExternalLink className="w-3.5 h-3.5" />
                    </div>
                  </Link>
                );
              })}
            </div>
          </div>

          {/* Recent Scans */}
          <div className="card">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-foreground">Recent Scans</h2>
              <Link to="/scans" className="text-sm text-accent-blue hover:underline">View all</Link>
            </div>
            {recentScans.length === 0 ? (
              <div className="text-center py-8 text-foreground-secondary">
                <Container className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p>No scans yet</p>
                <p className="text-sm mt-1">Start by scanning a Dockerfile, image, or repository</p>
                <div className="mt-4 flex gap-2 justify-center">
                  <Link to="/dockerfile" className="btn-primary text-sm">Scan Dockerfile</Link>
                  <Link to="/docker" className="btn-secondary text-sm">Scan Image</Link>
                </div>
              </div>
            ) : (
              <div className="table-container">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Target</th>
                      <th>Status</th>
                      <th>Findings</th>
                      <th>Date</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentScans.map((scan) => (
                      <tr key={scan.id}>
                        <td>
                          <span className="badge badge-info capitalize">{scan.type.replace('_', ' ')}</span>
                        </td>
                        <td className="font-mono text-sm max-w-[200px] truncate">{scan.target?.value || 'Unknown'}</td>
                        <td>
                          <span className={clsx('badge', {
                            'badge-success': scan.status === 'completed',
                            'badge-critical': scan.status === 'failed',
                            'badge-medium': scan.status === 'running',
                            'badge-info': scan.status === 'pending'
                          })}>
                            {scan.status}
                          </span>
                        </td>
                        <td>
                          {scan.summary && (
                            <div className="flex items-center gap-1">
                              {scan.summary.critical > 0 && <span className="badge badge-critical">{scan.summary.critical}</span>}
                              {scan.summary.high > 0 && <span className="badge badge-high">{scan.summary.high}</span>}
                              {scan.summary.medium > 0 && <span className="badge badge-medium">{scan.summary.medium}</span>}
                              {scan.summary.low > 0 && <span className="badge badge-low">{scan.summary.low}</span>}
                              {scan.summary.info > 0 && <span className="badge badge-info">{scan.summary.info}</span>}
                              {(scan.summary.totalFindings || 0) === 0 && <span className="badge badge-success">Clean</span>}
                            </div>
                          )}
                        </td>
                        <td className="text-foreground-secondary">
                          {formatDistanceToNow(new Date(scan.createdAt), { addSuffix: true })}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>

        {/* Right Column - Recent Jobs */}
        <div className="space-y-6">
          <div className="card">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-foreground">Recent Jobs</h2>
              <Link to="/scans" className="text-sm text-accent-blue hover:underline">View all</Link>
            </div>
            {recentJobs.length === 0 ? (
              <div className="text-center py-8 text-foreground-secondary">
                <Zap className="w-12 h-12 mx-auto mb-3 opacity-50" />
                <p>No jobs running</p>
                <p className="text-sm mt-1">Jobs appear here when you start scans or fixes</p>
              </div>
            ) : (
              <div className="space-y-3">
                {recentJobs.map((job) => (
                  <div key={job.id} className="flex items-center gap-3 p-3 bg-background-tertiary rounded-lg">
                    <div className={clsx('p-2 rounded-lg', getStatusColor(job.status).replace('text-', 'bg-') + '/10')}>
                      {getStatusIcon(job.status)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="font-medium text-foreground truncate">{job.type.replace('_', ' ')}</p>
                      <p className="text-sm text-foreground-secondary truncate">{job.currentStep || 'Queued'}</p>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="w-20">
                        <div className="progress-bar">
                          <div
                            className="progress-fill"
                            style={{ width: `${job.progress}%` }}
                          />
                        </div>
                      </div>
                      <span className={clsx('text-sm font-medium', getStatusColor(job.status))}>
                        {job.status}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* System Health */}
          <div className="card">
            <h2 className="text-lg font-semibold text-foreground mb-4">System Health</h2>
            <div className="grid grid-cols-2 gap-4">
              <div className="p-3 bg-background-tertiary rounded-lg">
                <p className="text-sm text-foreground-secondary">API Status</p>
                <p className="font-medium text-accent-green flex items-center gap-1">
                  <CheckCircle className="w-4 h-4" /> Operational
                </p>
              </div>
              <div className="p-3 bg-background-tertiary rounded-lg">
                <p className="text-sm text-foreground-secondary">Job Queue</p>
                <p className="font-medium text-accent-blue flex items-center gap-1">
                  <Clock className="w-4 h-4" /> {recentJobs.filter(j => j.status === 'queued').length} queued
                </p>
              </div>
              <div className="p-3 bg-background-tertiary rounded-lg">
                <p className="text-sm text-foreground-secondary">Active Scans</p>
                <p className="font-medium text-accent-blue flex items-center gap-1">
                  <Zap className="w-4 h-4" /> {recentJobs.filter(j => ['running', 'analyzing', 'fixing'].includes(j.status)).length} running
                </p>
              </div>
              <div className="p-3 bg-background-tertiary rounded-lg">
                <p className="text-sm text-foreground-secondary">AI Service</p>
                <p className="font-medium text-accent-green flex items-center gap-1">
                  <CheckCircle className="w-4 h-4" /> Connected
                </p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}