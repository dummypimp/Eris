'use client';

import React, { createContext, useContext, useEffect, useState } from 'react';
import { AuthUser } from '@/lib/types';
import { apiClient } from '@/lib/api-client';
import { wsClient } from '@/lib/websocket-client';
import Cookies from 'js-cookie';
import { jwtDecode } from 'jwt-decode';

interface AuthContextType {
  user: AuthUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<{ success: boolean; error?: string }>;
  logout: () => void;
  hasPermission: (permission: string) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: React.ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    checkAuthStatus();
  }, []);

  const checkAuthStatus = async () => {
    setIsLoading(true);
    try {
      const token = Cookies.get('auth_token');
      if (!token) {
        setIsLoading(false);
        return;
      }

      const decoded: any = jwtDecode(token);
      const currentTime = Date.now() / 1000;

      if (decoded.exp < currentTime) {

        Cookies.remove('auth_token');
        setUser(null);
        setIsLoading(false);
        return;
      }

      const userData: AuthUser = {
        id: decoded.sub,
        username: decoded.username,
        role: decoded.role,
        permissions: decoded.permissions || [],
        lastLogin: decoded.lastLogin,
      };

      setUser(userData);

      try {
        await wsClient.connect();
      } catch (error) {
        console.error('Failed to connect to WebSocket:', error);
      }
    } catch (error) {
      console.error('Auth check failed:', error);
      Cookies.remove('auth_token');
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  };

  const login = async (username: string, password: string) => {
    try {
      const response = await apiClient.login(username, password);

      if (response.success && response.data) {

        Cookies.set('auth_token', response.data.token, {
          expires: 7,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'strict'
        });

        setUser(response.data.user);

        try {
          await wsClient.connect();
        } catch (error) {
          console.error('Failed to connect to WebSocket:', error);
        }

        return { success: true };
      } else {
        return { success: false, error: response.error || 'Login failed' };
      }
    } catch (error: any) {
      return { success: false, error: error.message || 'Login failed' };
    }
  };

  const logout = async () => {
    try {
      await apiClient.logout();
    } catch (error) {

    } finally {
      setUser(null);
      wsClient.disconnect();

    }
  };

  const hasPermission = (permission: string): boolean => {
    if (!user) return false;
    return user.permissions.includes(permission) || user.role === 'admin';
  };

  const value: AuthContextType = {
    user,
    isAuthenticated: !!user,
    isLoading,
    login,
    logout,
    hasPermission,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};