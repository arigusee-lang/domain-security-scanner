import { writable } from 'svelte/store';

export interface AuthUser {
  id: string;
  email: string;
  name: string | null;
  avatarUrl: string | null;
  plan: 'registered' | 'pro' | 'enterprise';
}

export const currentUser = writable<AuthUser | null>(null);
export const authLoading = writable(true);

export async function fetchCurrentUser(): Promise<void> {
  authLoading.set(true);
  try {
    const res = await fetch('/api/auth/me', { credentials: 'include' });
    if (res.ok) {
      const data = await res.json();
      currentUser.set(data);
    } else {
      currentUser.set(null);
    }
  } catch {
    currentUser.set(null);
  } finally {
    authLoading.set(false);
  }
}
