import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Mail,
  Lock,
  Eye,
  EyeOff,
  Github,
  Gitlab,
  GitFork,
  AlertCircle,
  Loader2,
  Shield
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { toast } from 'react-hot-toast';
import { clsx } from 'clsx';

export function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [remember, setRemember] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});

  const validate = () => {
    const newErrors: Record<string, string> = {};
    if (!email.trim()) newErrors.email = 'Email is required';
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) newErrors.email = 'Invalid email format';
    if (!password) newErrors.password = 'Password is required';
    else if (password.length < 8) newErrors.password = 'Password must be at least 8 characters';
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate()) return;

    setLoading(true);
    try {
      await login({ email, password, rememberMe: remember });
      toast.success('Welcome back!');
      navigate('/dashboard');
    } catch (err: any) {
      toast.error(err?.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  const handleOAuthLogin = (provider: 'github' | 'gitlab' | 'bitbucket') => {
    window.location.href = `/api/auth/${provider}`;
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-gradient-to-br from-background via-background-tertiary to-background">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="text-center mb-8">
          <Link to="/" className="inline-flex items-center gap-2 text-2xl font-bold text-foreground">
            <Shield className="w-8 h-8 text-accent-blue" />
            <span>DevSecOps AI</span>
          </Link>
        </div>

        {/* Login Card */}
        <div className="card p-8">
          <div className="text-center mb-8">
            <h1 className="text-2xl font-bold text-foreground">Welcome back</h1>
            <p className="text-foreground-secondary mt-2">Sign in to your DevSecOps AI Platform account</p>
          </div>

          {/* Social Login */}
          <div className="space-y-3 mb-6">
            <button
              type="button"
              className="btn-secondary w-full flex items-center justify-center gap-2"
              onClick={() => handleOAuthLogin('github')}
            >
              <Github className="w-5 h-5" />
              Continue with GitHub
            </button>
            <button
              type="button"
              className="btn-secondary w-full flex items-center justify-center gap-2"
              onClick={() => handleOAuthLogin('gitlab')}
            >
              <Gitlab className="w-5 h-5" />
              Continue with GitLab
            </button>
            <button
              type="button"
              className="btn-secondary w-full flex items-center justify-center gap-2"
              onClick={() => handleOAuthLogin('bitbucket')}
            >
              <GitFork className="w-5 h-5" />
              Continue with Bitbucket
            </button>
          </div>

          {/* Divider */}
          <div className="relative mb-6">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-border" />
            </div>
            <div className="relative flex justify-center text-sm">
              <span className="px-4 bg-background text-foreground-muted">Or continue with email</span>
            </div>
          </div>

          {/* Email/Password Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="email" className="label">Email Address</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-foreground-muted" />
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => { setEmail(e.target.value); setErrors(prev => ({ ...prev, email: '' })); }}
                  placeholder="you@example.com"
                  className={clsx('input pl-10', errors.email && 'border-severity-critical')}
                  autoComplete="email"
                  disabled={loading}
                />
              </div>
              {errors.email && (
                <p className="text-sm text-severity-critical mt-1 flex items-center gap-1">
                  <AlertCircle className="w-3.5 h-3.5" />
                  {errors.email}
                </p>
              )}
            </div>

            <div>
              <label htmlFor="password" className="label">Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-foreground-muted" />
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => { setPassword(e.target.value); setErrors(prev => ({ ...prev, password: '' })); }}
                  placeholder="••••••••"
                  className={clsx('input pl-10 pr-10', errors.password && 'border-severity-critical')}
                  autoComplete="current-password"
                  disabled={loading}
                />
                <button
                  type="button"
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-foreground-muted hover:text-foreground"
                  onClick={() => setShowPassword(!showPassword)}
                  disabled={loading}
                >
                  {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                </button>
              </div>
              {errors.password && (
                <p className="text-sm text-severity-critical mt-1 flex items-center gap-1">
                  <AlertCircle className="w-3.5 h-3.5" />
                  {errors.password}
                </p>
              )}
            </div>

            <div className="flex items-center justify-between">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  checked={remember}
                  onChange={(e) => setRemember(e.target.checked)}
                  className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue"
                  disabled={loading}
                />
                <span className="text-sm text-foreground-secondary">Remember me</span>
              </label>
              <Link to="/forgot-password" className="text-sm text-accent-blue hover:underline">
                Forgot password?
              </Link>
            </div>

            <button
              type="submit"
              className="btn-primary w-full py-3"
              disabled={loading}
            >
              {loading ? (
                <div className="flex items-center justify-center gap-2">
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Signing in...
                </div>
              ) : (
                'Sign In'
              )}
            </button>
          </form>
        </div>

        {/* Footer */}
        <div className="text-center mt-6 text-sm text-foreground-secondary">
          <p>Don't have an account? <Link to="/register" className="text-accent-blue hover:underline font-medium">Sign up</Link></p>
          <p className="mt-2">By signing in, you agree to our <Link to="/terms" className="text-accent-blue hover:underline">Terms of Service</Link> and <Link to="/privacy" className="text-accent-blue hover:underline">Privacy Policy</Link></p>
        </div>

        {/* Demo Credentials Hint */}
        <div className="mt-6 p-4 bg-background-tertiary rounded-lg">
          <p className="text-xs text-foreground-muted text-center">
            <strong>Demo:</strong> Use any email/password (min 8 chars) to test the UI.
            Backend validation will be implemented with real auth.
          </p>
        </div>
      </div>
    </div>
  );
}