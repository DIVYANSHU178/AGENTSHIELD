import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  ReactNode,
} from 'react';
import {
  UserIdentity,
  Role,
  Permission,
  ROLE_PERMISSIONS,
} from '../types';
import {
  login as apiLogin,
  logout as apiLogout,
  fetchCurrentUser,
  getStoredToken,
  clearStoredToken,
  onUnauthorized,
} from '../lib/api';

interface AuthContextType {
  isAuthenticated: boolean;
  user: UserIdentity | null;
  token: string | null;
  roles: Role[];
  loading: boolean;
  error: string | null;
  showLoginModal: boolean;
  setShowLoginModal: (show: boolean) => void;
  login: (username: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  hasRole: (role: Role) => boolean;
  hasPermission: (permission: Permission) => boolean;
  canResolveApprovals: boolean;
  canCancelApproval: boolean;
  canRunScenarioLab: boolean;
  canManageIdentities: boolean;
  clearError: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<UserIdentity | null>(null);
  const [token, setToken] = useState<string | null>(getStoredToken());
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [showLoginModal, setShowLoginModal] = useState<boolean>(false);

  const checkCurrentSession = useCallback(async () => {
    const currentToken = getStoredToken();
    if (!currentToken) {
      setUser(null);
      setToken(null);
      setLoading(false);
      return;
    }

    try {
      const identity = await fetchCurrentUser();
      if (identity && identity.is_active) {
        setUser(identity);
        setToken(currentToken);
        setError(null);
      } else {
        clearStoredToken();
        setUser(null);
        setToken(null);
      }
    } catch (err: any) {
      // 401 or token expired/revoked: clear token
      clearStoredToken();
      setUser(null);
      setToken(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    checkCurrentSession();

    // Register callback for centralized 401 handling
    const unsubscribe = onUnauthorized(() => {
      setUser(null);
      setToken(null);
      setError('Session expired or revoked. Please sign in again.');
    });

    return () => unsubscribe();
  }, [checkCurrentSession]);

  const login = async (username: string, password: string): Promise<void> => {
    setError(null);
    try {
      const resp = await apiLogin({ username: username.trim(), password });
      setToken(resp.session_id);
      // Fetch full identity profile
      const identity = await fetchCurrentUser();
      setUser(identity);
    } catch (err: any) {

      const msg = err.message || 'Authentication failed. Please verify credentials.';
      setError(msg);
      throw err;
    }
  };

  const logout = async (): Promise<void> => {
    try {
      await apiLogout();
    } finally {
      clearStoredToken();
      setUser(null);
      setToken(null);
      setError(null);
    }
  };

  const hasRole = useCallback(
    (role: Role): boolean => {
      if (!user || !user.is_active) return false;
      return user.roles.includes(role);
    },
    [user]
  );

  const hasPermission = useCallback(
    (permission: Permission): boolean => {
      if (!user || !user.is_active) return false;
      return user.roles.some((role) => ROLE_PERMISSIONS[role]?.includes(permission));
    },
    [user]
  );

  const roles = user ? user.roles : [];
  const isAuthenticated = Boolean(user && user.is_active && token);

  const canResolveApprovals = hasPermission('RESOLVE_APPROVALS');
  const canCancelApproval = hasPermission('CANCEL_APPROVAL');
  const canRunScenarioLab = hasPermission('RUN_SCENARIO_LAB');
  const canManageIdentities = hasPermission('MANAGE_IDENTITIES');

  const clearError = useCallback(() => setError(null), []);

  const value: AuthContextType = {
    isAuthenticated,
    user,
    token,
    roles,
    loading,
    error,
    showLoginModal,
    setShowLoginModal,
    login,
    logout,
    hasRole,
    hasPermission,
    canResolveApprovals,
    canCancelApproval,
    canRunScenarioLab,
    canManageIdentities,
    clearError,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export function useAuth(): AuthContextType {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
