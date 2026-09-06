/**
 * Motion Context & Reduced-Motion Controller
 * Phase 14J-C1 UI Hardening Foundation
 *
 * Manages motion preferences, detects system-level prefers-reduced-motion,
 * and distributes accessibility-safe variant mappings throughout the application tree.
 */

import React, { createContext, useContext, useState, useEffect, useMemo, useCallback } from 'react';
import { type Variants } from 'framer-motion';
import { getMotionVariant } from '../theme/motion';

interface MotionContextValue {
  isReducedMotion: boolean;
  userMotionPreference: 'system' | 'reduced' | 'full';
  setUserMotionPreference: (pref: 'system' | 'reduced' | 'full') => void;
  getVariant: (name: 'page' | 'modal' | 'card' | 'row' | 'tab' | 'toast' | 'pulse' | 'container') => Variants;
}

const MotionContext = createContext<MotionContextValue | undefined>(undefined);

const STORAGE_KEY = 'agentshield_motion_preference';

export const MotionProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [systemPrefersReduced, setSystemPrefersReduced] = useState<boolean>(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return false;
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  });

  const [userPref, setUserPref] = useState<'system' | 'reduced' | 'full'>(() => {
    if (typeof window === 'undefined') return 'system';
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored === 'reduced' || stored === 'full' || stored === 'system') {
        return stored;
      }
    } catch {
      // Ignore storage errors in test / incognito
    }
    return 'system';
  });

  // Listen to OS-level prefers-reduced-motion media query
  useEffect(() => {
    if (typeof window === 'undefined' || !window.matchMedia) return;
    const mediaQuery = window.matchMedia('(prefers-reduced-motion: reduce)');

    const handler = (event: MediaQueryListEvent) => {
      setSystemPrefersReduced(event.matches);
    };

    if (mediaQuery.addEventListener) {
      mediaQuery.addEventListener('change', handler);
      return () => mediaQuery.removeEventListener('change', handler);
    } else if ((mediaQuery as any).addListener) {
      (mediaQuery as any).addListener(handler);
      return () => (mediaQuery as any).removeListener(handler);
    }
  }, []);

  const setUserMotionPreference = useCallback((pref: 'system' | 'reduced' | 'full') => {
    setUserPref(pref);
    try {
      localStorage.setItem(STORAGE_KEY, pref);
    } catch {
      // Ignore storage errors
    }
  }, []);

  // Effective reduced motion state
  const isReducedMotion = useMemo(() => {
    if (userPref === 'reduced') return true;
    if (userPref === 'full') return false;
    return systemPrefersReduced;
  }, [userPref, systemPrefersReduced]);

  const getVariant = useCallback(
    (name: 'page' | 'modal' | 'card' | 'row' | 'tab' | 'toast' | 'pulse' | 'container'): Variants => {
      return getMotionVariant(name, isReducedMotion);
    },
    [isReducedMotion]
  );

  const value = useMemo(
    () => ({
      isReducedMotion,
      userMotionPreference: userPref,
      setUserMotionPreference,
      getVariant,
    }),
    [isReducedMotion, userPref, setUserMotionPreference, getVariant]
  );

  return <MotionContext.Provider value={value}>{children}</MotionContext.Provider>;
};

export function useMotion(): MotionContextValue {
  const context = useContext(MotionContext);
  if (!context) {
    // Fallback safe defaults if used outside provider
    return {
      isReducedMotion: false,
      userMotionPreference: 'system',
      setUserMotionPreference: () => {},
      getVariant: (name) => getMotionVariant(name, false),
    };
  }
  return context;
}
