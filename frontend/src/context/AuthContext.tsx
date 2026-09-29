import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';
import { insforge } from '../lib/insforge';
import { clearStoredSession, rememberSession, restoreSession } from '../lib/session';
import { completeOAuthCallback, OAuthProvider, startOAuth } from '../lib/oauth';
import { User } from '@devsecops/shared/types';

/** Thrown by register() when the new account still has to confirm its email. */
export const VERIFY_EMAIL = 'VERIFY_EMAIL';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  /** Why the last OAuth round trip failed, if it did. Shown on the sign-in page. */
  oauthError: string | null;
  clearOauthError: () => void;
  login: (credentials: { email: string; password: string; rememberMe?: boolean }) => Promise<void>;
  register: (data: { name: string; email: string; password: string }) => Promise<void>;
  loginWithProvider: (provider: OAuthProvider, returnTo?: string) => Promise<never>;
  verifyEmail: (data: { email: string; otp: string }) => Promise<void>;
  resendVerificationEmail: (email: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshUser: () => Promise<void>;
  updateUser: (data: Partial<User>) => Promise<void>;
  updateProfile: (data: Partial<User>) => Promise<void>;
  isAuthenticated: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [oauthError, setOauthError] = useState<string | null>(null);

  const refreshUser = useCallback(async () => {
    try {
      const response = await api.get('/auth/me');
      setUser(response.data.data);
    } catch {
      setUser(null);
    }
  }, []);

  /**
   * InsForge persists the session itself, so a page load only has to ask whether
   * one exists and then resolve the profile through the API.
   *
   * The one extra case is the OAuth return trip: the provider sends the user
   * back to the app with ?insforge_code= in the URL, and that exchange has to
   * happen before anything else or the session is lost on the next reload.
   */
  useEffect(() => {
    let cancelled = false;

    (async () => {
      try {
        // Rehydrates the SDK from the mirrored session, refreshing if expired.
        const token = await restoreSession();
        if (cancelled) return;
        if (token) {
          await refreshUser();
          return;
        }
        // Non-null only when this load is an OAuth return trip, in which case a
        // session now exists. A plain signed-out load skips the API call.
        if (await completeOAuthCallback()) {
          await refreshUser();
        }
      } catch (err) {
        // A failed OAuth exchange still has to land on a usable page, so the
        // reason is kept for the sign-in screen to show instead of failing silently.
        if (!cancelled) {
          setOauthError(err instanceof Error ? err.message : 'Sign-in could not be completed');
          setUser(null);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [refreshUser]);

  const login = async ({ email, password }: { email: string; password: string }) => {
    const { data, error } = await insforge.auth.signInWithPassword({ email, password });
    if (error) throw new Error(error.message);
    if (!data?.accessToken) throw new Error('Sign-in did not return a session');
    rememberSession(data.accessToken, data.refreshToken);
    await refreshUser();
  };

  const register = async ({ name, email, password }: { name: string; email: string; password: string }) => {
    // redirectTo is only used by the link-based verification method; the
    // project runs on the code method, where the app asks for the code itself.
    const { data, error } = await insforge.auth.signUp({
      email,
      password,
      name,
      redirectTo: `${window.location.origin}/verify-email`
    });
    if (error) throw new Error(error.message);

    // Email verification is on for this project, so signUp returns no session
    // until the emailed code is confirmed.
    if (data?.requireEmailVerification || !data?.accessToken) {
      throw new Error(VERIFY_EMAIL);
    }
    rememberSession(data.accessToken, data.refreshToken);
    await refreshUser();
  };

  const verifyEmail = async ({ email, otp }: { email: string; otp: string }) => {
    const { data, error } = await insforge.auth.verifyEmail({ email, otp });
    if (error) throw new Error(error.message);
    // A successful verification returns a session, so the user lands signed in
    // instead of being bounced to the sign-in form for a second time.
    if (!data?.accessToken) throw new Error('Verification succeeded but no session was returned');
    rememberSession(data.accessToken, data.refreshToken);
    await refreshUser();
  };

  const resendVerificationEmail = async (email: string) => {
    const { error } = await insforge.auth.resendVerificationEmail({
      email,
      redirectTo: `${window.location.origin}/verify-email`
    });
    if (error) throw new Error(error.message);
  };

  const loginWithProvider = async (provider: OAuthProvider, returnTo = '/'): Promise<never> => {
    setOauthError(null);
    return startOAuth(provider, returnTo);
  };

  const logout = async () => {
    try {
      await api.post('/auth/logout');
    } catch {
      // The session is cleared client-side regardless.
    } finally {
      clearStoredSession();
      await insforge.auth.signOut();
      setUser(null);
    }
  };

  const updateUser = async (data: Partial<User>) => {
    const response = await api.patch('/auth/me', data);
    setUser(response.data.data);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        oauthError,
        clearOauthError: () => setOauthError(null),
        login,
        register,
        loginWithProvider,
        verifyEmail,
        resendVerificationEmail,
        logout,
        refreshUser,
        updateUser,
        updateProfile: updateUser,
        isAuthenticated: !!user
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
