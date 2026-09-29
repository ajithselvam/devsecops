import React, { useEffect, useRef, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { MailCheck, AlertCircle, Loader2, Shield, ArrowLeft } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { toast } from 'react-hot-toast';
import { clsx } from 'clsx';

const CODE_LENGTH = 6;
const RESEND_COOLDOWN_SECONDS = 30;

/**
 * Second step of sign-up. The InsForge project has email verification on with
 * the code method, so signUp() returns no session and the code has to be typed
 * in here; verifyEmail() then hands back a session and the user is signed in.
 */
export function VerifyEmail() {
  const { verifyEmail, resendVerificationEmail } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email] = useState(() => {
    const state = location.state as { email?: string } | null;
    return state?.email ?? new URLSearchParams(location.search).get('email') ?? '';
  });
  const [digits, setDigits] = useState<string[]>(() => Array(CODE_LENGTH).fill(''));
  const [loading, setLoading] = useState(false);
  const [resending, setResending] = useState(false);
  const [cooldown, setCooldown] = useState(0);
  const [error, setError] = useState('');
  const inputs = useRef<Array<HTMLInputElement | null>>([]);

  useEffect(() => {
    inputs.current[0]?.focus();
  }, []);

  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setTimeout(() => setCooldown((s) => s - 1), 1000);
    return () => clearTimeout(timer);
  }, [cooldown]);

  const code = digits.join('');
  const complete = code.length === CODE_LENGTH;

  const setDigit = (index: number, value: string) => {
    // One box per character; a paste or a full code lands in the first box and
    // is spread out from there.
    const cleaned = value.replace(/\D/g, '');
    if (!cleaned) {
      setDigits((prev) => prev.map((d, i) => (i === index ? '' : d)));
      return;
    }
    if (cleaned.length > 1) {
      const spread = cleaned.slice(0, CODE_LENGTH).split('');
      setDigits((prev) => prev.map((_, i) => spread[i] ?? ''));
      inputs.current[Math.min(spread.length, CODE_LENGTH - 1)]?.focus();
      return;
    }
    setDigits((prev) => prev.map((d, i) => (i === index ? cleaned : d)));
    if (index < CODE_LENGTH - 1) inputs.current[index + 1]?.focus();
  };

  const handleKeyDown = (index: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !digits[index] && index > 0) {
      inputs.current[index - 1]?.focus();
    }
    if (e.key === 'ArrowLeft' && index > 0) inputs.current[index - 1]?.focus();
    if (e.key === 'ArrowRight' && index < CODE_LENGTH - 1) inputs.current[index + 1]?.focus();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) {
      setError('No email address to verify. Start again from the sign-up form.');
      return;
    }
    if (!complete) {
      setError(`Enter all ${CODE_LENGTH} digits of the code`);
      return;
    }

    setLoading(true);
    setError('');
    try {
      await verifyEmail({ email, otp: code });
      toast.success('Email verified. Welcome aboard!');
      navigate('/', { replace: true });
    } catch (err: any) {
      setError(err?.message || 'That code was not accepted');
      setDigits(Array(CODE_LENGTH).fill(''));
      inputs.current[0]?.focus();
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    if (!email) return;
    setResending(true);
    try {
      await resendVerificationEmail(email);
      toast.success('A new code is on its way');
      setCooldown(RESEND_COOLDOWN_SECONDS);
    } catch (err: any) {
      toast.error(err?.message || 'Could not resend the code');
    } finally {
      setResending(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-gradient-to-br from-background via-background-tertiary to-background">
      <div className="w-full max-w-md">
        <div className="text-center mb-8">
          <Link to="/" className="inline-flex items-center gap-2 text-2xl font-bold text-foreground">
            <Shield className="w-8 h-8 text-accent-blue" />
            <span>DevSecOps AI</span>
          </Link>
        </div>

        <div className="card p-8">
          <div className="text-center mb-8">
            <MailCheck className="w-10 h-10 text-accent-blue mx-auto mb-3" />
            <h1 className="text-2xl font-bold text-foreground">Verify your email</h1>
            <p className="text-foreground-secondary mt-2">
              We sent a {CODE_LENGTH}-digit code to{' '}
              <span className="text-foreground font-medium break-all">{email || 'your inbox'}</span>.
              Enter it below to finish creating your account.
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="flex justify-center gap-2">
              {digits.map((digit, index) => (
                <input
                  key={index}
                  ref={(el) => { inputs.current[index] = el; }}
                  type="text"
                  inputMode="numeric"
                  autoComplete={index === 0 ? 'one-time-code' : 'off'}
                  maxLength={CODE_LENGTH}
                  value={digit}
                  onChange={(e) => { setError(''); setDigit(index, e.target.value); }}
                  onKeyDown={(e) => handleKeyDown(index, e)}
                  onPaste={(e) => {
                    e.preventDefault();
                    setError('');
                    setDigit(index, e.clipboardData.getData('text'));
                  }}
                  className={clsx(
                    'w-11 h-14 text-center text-xl font-semibold text-foreground bg-background-tertiary',
                    'border border-border rounded-lg focus:outline-none focus:border-accent-blue',
                    error && 'border-severity-critical'
                  )}
                  disabled={loading}
                  aria-label={`Digit ${index + 1} of ${CODE_LENGTH}`}
                />
              ))}
            </div>

            {error && (
              <p className="text-sm text-severity-critical flex items-start gap-1">
                <AlertCircle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                {error}
              </p>
            )}

            <button type="submit" className="btn-primary w-full py-3" disabled={loading || !complete}>
              {loading ? (
                <div className="flex items-center justify-center gap-2">
                  <Loader2 className="w-5 h-5 animate-spin" />
                  Verifying...
                </div>
              ) : (
                'Verify email'
              )}
            </button>
          </form>

          <div className="mt-6 text-center text-sm text-foreground-secondary">
            <p>
              Did not get it?{' '}
              <button
                type="button"
                onClick={handleResend}
                disabled={resending || cooldown > 0}
                className="text-accent-blue hover:underline font-medium disabled:text-foreground-muted disabled:no-underline disabled:cursor-not-allowed"
              >
                {cooldown > 0 ? `Resend in ${cooldown}s` : 'Resend code'}
              </button>
            </p>
            <p className="mt-3">
              <Link to="/register" className="inline-flex items-center gap-1 text-accent-blue hover:underline font-medium">
                <ArrowLeft className="w-3.5 h-3.5" />
                Use a different account
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
