"use client";

import Link from 'next/link';
import { useAuth } from '@/components/auth/AuthProvider';
import { loginHref, signupHref } from '@/lib/authLinks';
import styles from './landing.module.css';

// What an account keeps, with the next step for visitors and for signed-in users.
export default function AccountBand() {
  const { status, user } = useAuth();
  const signedIn = status === 'signed-in' && user;
  const known = status !== 'loading';
  return (
    <section className={styles.band} aria-labelledby="account-band-title">
      <div className={styles.bandText}>
        <h2 id="account-band-title" className={styles.bandTitle}>
          {signedIn ? `Signed in as ${user.name}` : 'Your progress follows you'}
        </h2>
        <p>
          {signedIn
            ? 'Your completed labs, best scores and the lab you are working on are on your account page.'
            : 'Sign in on any device and pick up the lab you were working on. Completed labs, best scores and grade reports stay with your account.'}
        </p>
      </div>
      <div className={styles.bandActions}>
        {known && signedIn && (
          <>
            <Link href="/account" className={styles.button}>Open your account</Link>
            <Link href="/labs" className={styles.buttonQuiet}>Browse the labs</Link>
          </>
        )}
        {known && !signedIn && (
          <>
            <Link href={signupHref('/labs')} className={styles.button}>Create an account</Link>
            <Link href={loginHref('/labs')} className={styles.buttonQuiet}>Sign in</Link>
          </>
        )}
      </div>
    </section>
  );
}
