import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { api } from '../services/api';
import { insforge } from '../lib/insforge';
import { clearStoredSession, rememberSession, restoreSession } from '../lib/session';
import { User } from '@devsecops/shared/types';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  login: (credentials: { email: string; password: string; rememberMe?: boolean }) => Promise<void>;
  register: (data: { name: string; email: string; password: string }) => Promise<void>;
  loginWithProvider: (provider: 'github' | 'google') => Promise<void>;
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
   */
  useEffect(() => {
    let cancelled = false;

    (async () => {
      try {
        // Rehydrates the SDK from the mirrored session, refreshing if expired.
        const token = await restoreSession();
        if (cancelled) return;
        if (token) await refreshUser();
      } catch {
        if (!cancelled) setUser(null);
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
    const { data, error } = await insforge.auth.signUp({ email, password, name });
    if (error) throw new Error(error.message);

    // With email verification on, signUp returns no session until the code is
    // confirmed; the caller is told to check their inbox.
    if (!data?.accessToken) {
      throw new Error('VERIFY_EMAIL');
    }
    rememberSession(data.accessToken, data.refreshToken);
    await refreshUser();
  };

  const loginWithProvider = async (provider: 'github' | 'google') => {
    // The provider redirects away, so the session is captured on the next boot
    // by restoreSession() once InsForge redirects back.
    const { error } = await insforge.auth.signInWithOAuth({ provider, redirectTo: window.location.origin });
    if (error) throw new Error(error.message);
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
        login,
        register,
        loginWithProvider,
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
