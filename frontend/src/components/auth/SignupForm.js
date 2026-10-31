"use client";

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { apiErrorMessage } from '@/lib/api';
import { loginHref, safeNext } from '@/lib/authLinks';
import { useAuth } from './AuthProvider';
import AuthShell from './AuthShell';
import PasswordField from './PasswordField';
import styles from './auth.module.css';

const MIN_PASSWORD = 8;

export default function SignupForm({ next: requestedNext }) {
  const router = useRouter();
  const { status, signUp } = useAuth();
  const next = safeNext(requestedNext);
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (status === 'signed-in') router.replace(next);
  }, [status, next, router]);

  const onSubmit = async event => {
    event.preventDefault();
    setError(null);
    if (password.length < MIN_PASSWORD) {
      setError(`Use at least ${MIN_PASSWORD} characters for your password.`);
      return;
    }
    setBusy(true);
    try {
      await signUp({ name, email, password });
    } catch (failure) {
      setError(apiErrorMessage(failure, 'The account could not be created. Try again.'));
      setBusy(false);
    }
  };

  return (
    <AuthShell
      title="Create your account"
      lead="Your progress and grade reports are saved to it, so you can continue on any device."
    >
      <form className={styles.form} onSubmit={onSubmit} noValidate>
        <div className={styles.field}>
          <label htmlFor="name" className={styles.label}>Name</label>
          <input
            id="name"
            name="name"
            type="text"
            className={styles.input}
            value={name}
            onChange={event => setName(event.target.value)}
            autoComplete="name"
            maxLength={60}
            required
          />
        </div>
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
          autoComplete="new-password"
          minLength={MIN_PASSWORD}
          hint={`At least ${MIN_PASSWORD} characters. A short phrase is easier to remember than random symbols.`}
        />
        {error && <p className={styles.error} role="alert">{error}</p>}
        <button type="submit" className={styles.submit} disabled={busy}>
          {busy ? 'Creating your account…' : 'Create account'}
        </button>
      </form>
      <p className={styles.switch}>
        Already have an account? <Link href={loginHref(next)}>Sign in</Link>
      </p>
    </AuthShell>
  );
}
