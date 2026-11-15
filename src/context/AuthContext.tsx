"use client";

import React, { createContext, useContext, useEffect, useState } from "react";
import { User, Session, AuthError } from "@supabase/supabase-js";
import { supabase } from "@/lib/supabase/client";
import { getSupabaseConfig } from "@/lib/supabase/config";

interface AuthContextType {
  user: User | null;
  session: Session | null;
  loading: boolean;
  isConfigured: boolean;
  signIn: (email: string, password: string) => Promise<{ error: AuthError | Error | null }>;
  signUp: (email: string, password: string, fullName?: string) => Promise<{ error: AuthError | Error | null }>;
  signOut: () => Promise<void>;
  resetPassword: (email: string) => Promise<{ error: AuthError | Error | null }>;
  signInDemo: () => void;
  signInWithOAuth: (
    provider: "google" | "github",
    redirectPath?: string
  ) => Promise<{ error: AuthError | Error | null }>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(() => {
    if (typeof window !== "undefined") {
      const stored = localStorage.getItem("malguard_demo_user");
      if (stored) {
        try {
          return JSON.parse(stored);
        } catch {
          localStorage.removeItem("malguard_demo_user");
        }
      }
    }
    return null;
  });
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(() => getSupabaseConfig().isConfigured);
  const [isConfigured] = useState(() => getSupabaseConfig().isConfigured);

  useEffect(() => {
    if (isConfigured) {
      // 1. Fetch initial session from Supabase
      supabase.auth.getSession().then(({ data: { session: initialSession } }) => {
        setSession(initialSession);
        setUser(initialSession?.user ?? null);
        setLoading(false);
      });

      // 2. Listen for auth state changes
      const {
        data: { subscription },
      } = supabase.auth.onAuthStateChange((_event, currentSession) => {
        setSession(currentSession);
        setUser(currentSession?.user ?? null);
        setLoading(false);
      });

      return () => {
        subscription.unsubscribe();
      };
    }
  }, [isConfigured]);

  const signIn = async (email: string, password: string) => {
    if (!isConfigured) {
      return {
        error: new Error(
          "Supabase credentials are not configured in .env.local. Please add NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY to authenticate with live cloud Supabase, or use Demo Mode."
        ),
      };
    }

    try {
      const { error } = await supabase.auth.signInWithPassword({
        email,
        password,
      });
      return { error };
    } catch (err) {
      return { error: err as Error };
    }
  };

  const signUp = async (email: string, password: string, fullName?: string) => {
    if (!isConfigured) {
      return {
        error: new Error(
          "Supabase credentials are not configured in .env.local. Please configure your Supabase environment variables before signing up, or enter Demo Mode."
        ),
      };
    }

    try {
      const { error } = await supabase.auth.signUp({
        email,
        password,
        options: {
          data: {
            full_name: fullName,
          },
        },
      });
      return { error };
    } catch (err) {
      return { error: err as Error };
    }
  };

  const signOut = async () => {
    if (isConfigured) {
      await supabase.auth.signOut();
    }
    if (typeof window !== "undefined") {
      localStorage.removeItem("malguard_demo_user");
    }
    setUser(null);
    setSession(null);
  };

  const resetPassword = async (email: string) => {
    if (!isConfigured) {
      return {
        error: new Error(
          "Supabase credentials are not configured in .env.local. Password reset requires an active Supabase project configuration."
        ),
      };
    }

    try {
      const { error } = await supabase.auth.resetPasswordForEmail(email, {
        redirectTo: `${window.location.origin}/login`,
      });
      return { error };
    } catch (err) {
      return { error: err as Error };
    }
  };

  const signInDemo = () => {
    const demoUser = {
      id: "demo-analyst-uuid-2026",
      email: "analyst@malguard.ai",
      user_metadata: {
        full_name: "Lead Security Analyst",
        role: "SOC Lead",
      },
      created_at: new Date().toISOString(),
      app_metadata: { provider: "demo" },
      aud: "authenticated",
    } as unknown as User;

    setUser(demoUser);
    if (typeof window !== "undefined") {
      localStorage.setItem("malguard_demo_user", JSON.stringify(demoUser));
    }
  };

  const signInOAuth = async (
    provider: "google" | "github",
    redirectPath?: string
  ) => {
    if (!isConfigured) {
      return {
        error: new Error(
          "Supabase credentials are not configured in environment variables. Please add NEXT_PUBLIC_SUPABASE_URL and NEXT_PUBLIC_SUPABASE_ANON_KEY to enable OAuth authentication."
        ),
      };
    }

    try {
      const origin =
        typeof window !== "undefined" && window.location.origin
          ? window.location.origin
          : "";
      const destination = redirectPath || "/";
      const redirectUrl = origin
        ? `${origin}/auth/callback?next=${encodeURIComponent(destination)}`
        : undefined;

      const { error } = await supabase.auth.signInWithOAuth({
        provider,
        options: {
          redirectTo: redirectUrl,
        },
      });
      return { error };
    } catch (err) {
      return { error: err as Error };
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        session,
        loading,
        isConfigured,
        signIn,
        signUp,
        signOut,
        resetPassword,
        signInDemo,
        signInWithOAuth: signInOAuth,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}

