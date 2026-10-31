"use client";

// The signed-in account, shared by every page. The API keeps the session in an HttpOnly
// cookie; this context only mirrors who is signed in.

import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { api } from '@/lib/api';

const AuthContext = createContext(null);
const OWNER_KEY = 'netlabx_owner';

// The browser keeps a little lab state per account (running session, task marks). It must
// not leak to the next person who signs in on the same browser.
function clearLocalLabState() {
  try {
    const keys = [];
    for (let index = 0; index < localStorage.length; index += 1) {
      const key = localStorage.key(index);
      if (key && key.startsWith('netlabx_')) keys.push(key);
    }
    keys.forEach(key => localStorage.removeItem(key));
  } catch {
    // Storage unavailable: nothing to clear.
  }
}

function adoptOwner(user) {
  try {
    const previous = localStorage.getItem(OWNER_KEY);
    if (previous && previous !== String(user.id)) clearLocalLabState();
    localStorage.setItem(OWNER_KEY, String(user.id));
  } catch {
    // Storage unavailable.
  }
}

export function AuthProvider({ children }) {
  // status: loading | signed-in | signed-out | offline (the API did not answer)
  const [state, setState] = useState({ status: 'loading', user: null });

  // State changes happen in the promise callbacks only, so the mount effect can call this.
  const refresh = useCallback(() => api.getMe()
    .then(({ user }) => {
      if (!user) {
        setState({ status: 'signed-out', user: null });
        return null;
      }
      adoptOwner(user);
      setState({ status: 'signed-in', user });
      return user;
    })
    .catch(error => {
      if (error?.status === 401) {
        setState({ status: 'signed-out', user: null });
      } else {
        setState(current => (current.user ? current : { status: 'offline', user: null }));
      }
      return null;
    }), []);

  useEffect(() => { refresh(); }, [refresh]);

  const signIn = useCallback(async credentials => {
    const { user } = await api.login(credentials);
    adoptOwner(user);
    setState({ status: 'signed-in', user });
    return user;
  }, []);

  const signUp = useCallback(async details => {
    const { user } = await api.register(details);
    adoptOwner(user);
    setState({ status: 'signed-in', user });
    return user;
  }, []);

  const signOut = useCallback(async ({ everywhere = false } = {}) => {
    await api.logout({ everywhere });
    clearLocalLabState();
    setState({ status: 'signed-out', user: null });
  }, []);

  const value = useMemo(
    () => ({ ...state, refresh, signIn, signUp, signOut }),
    [state, refresh, signIn, signUp, signOut],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) throw new Error('useAuth must be used inside <AuthProvider>');
  return context;
}
