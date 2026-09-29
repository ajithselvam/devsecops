import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Mail,
  Lock,
  User,
  Eye,
  EyeOff,
  AlertCircle,
  Loader2,
  Shield
} from 'lucide-react';
import { useAuth, VERIFY_EMAIL } from '../context/AuthContext';
import { OAUTH_PROVIDERS, OAuthProvider } from '../lib/oauth';
import { toast } from 'react-hot-toast';
import { clsx } from 'clsx';
import { GoogleIcon, GitHubIcon } from '../components/ProviderIcons';

export function Register() {
  const { register, loginWithProvider } = useAuth();
  const navigate = useNavigate();
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [terms, setTerms] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [passwordStrength, setPasswordStrength] = useState(0);

  const checkPasswordStrength = (pwd: string) => {
    let strength = 0;
    if (pwd.length >= 8) strength++;
    if (pwd.length >= 12) strength++;
    if (/[A-Z]/.test(pwd)) strength++;
    if (/[a-z]/.test(pwd)) strength++;
    if (/[0-9]/.test(pwd)) strength++;
    if (/[^A-Za-z0-9]/.test(pwd)) strength++;
    setPasswordStrength(strength);
  };

  const validate = () => {
    const newErrors: Record<string, string> = {};
    if (!name.trim()) newErrors.name = 'Name is required';
    else if (name.trim().length < 2) newErrors.name = 'Name must be at least 2 characters';
    if (!email.trim()) newErrors.email = 'Email is required';
    else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) newErrors.email = 'Invalid email format';
    if (!password) newErrors.password = 'Password is required';
    else if (password.length < 8) newErrors.password = 'Password must be at least 8 characters';
    else if (passwordStrength < 3) newErrors.password = 'Password is too weak';
    if (password !== confirmPassword) newErrors.confirmPassword = 'Passwords do not match';
    if (!terms) newErrors.terms = 'You must accept the terms and conditions';
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!validate()) return;

    setLoading(true);
    try {
      await register({ name: name.trim(), email: email.trim(), password });
      toast.success('Account created successfully!');
      navigate('/', { replace: true });
    } catch (err: any) {
      if (err?.message === VERIFY_EMAIL) {
        toast.success('Account created. Enter the code we just emailed you.');
        // Sign-up returns no session until the code is confirmed, so the user
        // goes straight to the code screen instead of the sign-in form.
        navigate('/verify-email', { state: { email: email.trim() }, replace: true });
      } else {
        toast.error(err?.message || 'Registration failed');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleOAuthLogin = (provider: OAuthProvider) => {
    // Leaves the page for the provider, so no await and no busy state to reset.
    loginWithProvider(provider, '/').catch((err: Error) => toast.error(err.message));
  };

  const getStrengthColor = () => {
    if (passwordStrength <= 2) return 'bg-severity-critical';
    if (passwordStrength <= 4) return 'bg-severity-medium';
    return 'bg-accent-green';
  };

  const getStrengthLabel = () => {
    if (passwordStrength <= 2) return 'Weak';
    if (passwordStrength <= 4) return 'Medium';
    return 'Strong';
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

        {/* Register Card */}
        <div className="card p-8">
          <div className="text-center mb-8">
            <h1 className="text-2xl font-bold text-foreground">Create your account</h1>
            <p className="text-foreground-secondary mt-2">Join DevSecOps AI Platform to secure your infrastructure</p>
          </div>

          {/* Social Login */}
          <div className="space-y-3 mb-6">
            {OAUTH_PROVIDERS.map(({ id, label }) => (
              <button
                key={id}
                type="button"
                className="btn-secondary w-full flex items-center justify-center gap-2"
                onClick={() => handleOAuthLogin(id)}
              >
                {id === 'google' ? <GoogleIcon className="w-5 h-5" /> : <GitHubIcon className="w-5 h-5" />}
                Continue with {label}
              </button>
            ))}
          </div>

          {/* Divider */}
          <div className="relative mb-6">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-border" />
            </div>
            <div className="relative flex justify-center text-sm">
              <span className="px-4 bg-background text-foreground-muted">Or register with email</span>
            </div>
          </div>

          {/* Registration Form */}
          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="name" className="label">Full Name</label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-foreground-muted" />
                <input
                  id="name"
                  type="text"
                  value={name}
                  onChange={(e) => { setName(e.target.value); setErrors(prev => ({ ...prev, name: '' })); }}
                  placeholder="John Doe"
                  className={clsx('input pl-10', errors.name && 'border-severity-critical')}
                  autoComplete="name"
                  disabled={loading}
                />
              </div>
              {errors.name && (
                <p className="text-sm text-severity-critical mt-1 flex items-center gap-1">
                  <AlertCircle className="w-3.5 h-3.5" />
                  {errors.name}
                </p>
              )}
            </div>

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
                  onChange={(e) => { setPassword(e.target.value); checkPasswordStrength(e.target.value); setErrors(prev => ({ ...prev, password: '' })); }}
                  placeholder="••••••••"
                  className={clsx('input pl-10 pr-10', errors.password && 'border-severity-critical')}
                  autoComplete="new-password"
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
              {password && (
                <div className="mt-2">
                  <div className="h-1.5 bg-background-tertiary rounded-full overflow-hidden">
                    <div
                      className={`h-full transition-all duration-300 ${getStrengthColor()}`}
                      style={{ width: `${(passwordStrength / 6) * 100}%` }}
                    />
                  </div>
                  <p className="text-xs text-foreground-muted mt-1">Strength: {getStrengthLabel()}</p>
                </div>
              )}
              {errors.password && (
                <p className="text-sm text-severity-critical mt-1 flex items-center gap-1">
                  <AlertCircle className="w-3.5 h-3.5" />
                  {errors.password}
                </p>
              )}
            </div>

            <div>
              <label htmlFor="confirmPassword" className="label">Confirm Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-foreground-muted" />
                <input
                  id="confirmPassword"
                  type={showPassword ? 'text' : 'password'}
                  value={confirmPassword}
                  onChange={(e) => { setConfirmPassword(e.target.value); setErrors(prev => ({ ...prev, confirmPassword: '' })); }}
                  placeholder="••••••••"
                  className={clsx('input pl-10', errors.confirmPassword && 'border-severity-critical')}
                  autoComplete="new-password"
                  disabled={loading}
                />
              </div>
              {errors.confirmPassword && (
                <p className="text-sm text-severity-critical mt-1 flex items-center gap-1">
                  <AlertCircle className="w-3.5 h-3.5" />
                  {errors.confirmPassword}
                </p>
              )}
            </div>

            <div>
              <label className="flex items-start gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={terms}
                  onChange={(e) => { setTerms(e.target.checked); setErrors(prev => ({ ...prev, terms: '' })); }}
                  className="rounded border-border bg-background-tertiary text-accent-blue focus:ring-accent-blue mt-0.5"
                  disabled={loading}
                />
                <div className="text-sm text-foreground-secondary">
                  I agree to the <Link to="/terms" className="text-accent-blue hover:underline">Terms of Service</Link> and <Link to="/privacy" className="text-accent-blue hover:underline">Privacy Policy</Link>
                </div>
              </label>
              {errors.terms && (
                <p className="text-sm text-severity-critical mt-1 flex items-center gap-1">
                  <AlertCircle className="w-3.5 h-3.5" />
                  {errors.terms}
                </p>
              )}
            </div>

            <button
              type="submit"
              className="btn-primary w-full py-3"
              disabled={loading}
            >
              {loading ? (
                <div className="flex items-center justify-center gap-2">
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Creating account...
                </div>
              ) : (
                'Create Account'
              )}
            </button>
          </form>
        </div>

        {/* Footer */}
        <div className="text-center mt-6 text-sm text-foreground-secondary">
          <p>Already have an account? <Link to="/login" className="text-accent-blue hover:underline font-medium">Sign in</Link></p>
        </div>

        {/* Demo Credentials Hint */}
        <div className="mt-6 p-4 bg-background-tertiary rounded-lg">
          <p className="text-xs text-foreground-muted text-center">
            <strong>Demo:</strong> Any email/password works (min 8 chars).
            Real authentication with JWT will be implemented in the backend.
          </p>
        </div>
      </div>
    </div>
  );
}