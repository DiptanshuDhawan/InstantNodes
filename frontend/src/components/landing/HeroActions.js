"use client";

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { api } from '@/lib/api';
import { useAuth } from '@/components/auth/AuthProvider';
import { signupHref } from '@/lib/authLinks';
import styles from './landing.module.css';

// The hero buttons: visitors browse or create an account; signed-in users can go straight
// back into the lab they have running.
export default function HeroActions() {
  const { status, user } = useAuth();
  const userId = status === 'signed-in' ? user?.id : null;
  const [running, setRunning] = useState(null); // { userId, slug }

  useEffect(() => {
    if (userId == null) return undefined;
    let cancelled = false;
    api.getProgress()
      .then(progress => {
        if (!cancelled) setRunning({ userId, slug: progress?.active_session?.lab_slug || null });
      })
      .catch(() => { if (!cancelled) setRunning({ userId, slug: null }); });
    return () => { cancelled = true; };
  }, [userId]);

  const runningSlug = running?.userId === userId ? running.slug : null;

  if (userId != null && runningSlug) {
    return (
      <div className={styles.heroActions}>
        <Link href={`/labs/${runningSlug}`} className={styles.button}>Resume your lab</Link>
        <Link href="/labs" className={styles.buttonQuiet}>Browse the labs</Link>
      </div>
    );
  }
  return (
    <div className={styles.heroActions}>
      <Link href="/labs" className={styles.button}>Browse the labs</Link>
      {userId != null && (
        <Link href="/account" className={styles.buttonQuiet}>Your progress</Link>
      )}
      {status !== 'loading' && userId == null && (
        <Link href={signupHref('/labs')} className={styles.buttonQuiet}>Create an account</Link>
      )}
    </div>
  );
}
