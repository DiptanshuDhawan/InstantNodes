"use client";

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { apiErrorMessage } from '@/lib/api';
import { safeNext, signupHref } from '@/lib/authLinks';
import { useAuth } from './AuthProvider';
import AuthShell from './AuthShell';
import PasswordField from './PasswordField';
import styles from './auth.module.css';

export default function LoginForm({ next: requestedNext }) {
  const router = useRouter();
  const { status, signIn } = useAuth();
  const next = safeNext(requestedNext);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  // Already signed in (or just signed in): go where the user was heading.
  useEffect(() => {
    if (status === 'signed-in') router.replace(next);
  }, [status, next, router]);

  const onSubmit = async event => {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await signIn({ email, password });
    } catch (failure) {
      setError(apiErrorMessage(failure, 'Signing in did not work. Try again.'));
      setBusy(false);
    }
  };

  return (
    <AuthShell title="Sign in" lead="Pick up your labs where you left them.">
      <form className={styles.form} onSubmit={onSubmit} noValidate>
        <div className={styles.field}>
          <label htmlFor="email" className={styles.label}>Email</label>
          <input
            id="email"
            name="email"
            type="email"
            className={styles.input}
            value={email}
            onChange={event => setEmail(event.target.value)}
            autoComplete="email"
            maxLength={254}
            required
          />
        </div>
        <PasswordField
          id="password"
          label="Password"
          value={password}
          onChange={setPassword}
          autoComplete="current-password"
        />
        {error && <p className={styles.error} role="alert">{error}</p>}
        <button type="submit" className={styles.submit} disabled={busy}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
      <p className={styles.switch}>
        New to InstantNodes? <Link href={signupHref(next)}>Create an account</Link>
      </p>
    </AuthShell>
  );
}
