"use client";

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useAuth } from '@/components/auth/AuthProvider';
import { loginHref, signupHref } from '@/lib/authLinks';
import Logo from './Logo';
import styles from './site.module.css';

const NAV = [
  { href: '/labs', label: 'Labs', current: path => path === '/labs' || path.startsWith('/labs/') },
  { href: '/#how', label: 'How it works', narrow: false },
  { href: '/#simulated', label: 'What’s simulated', narrow: false },
];

export function initials(name) {
  const parts = String(name || '').trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return '?';
  const first = parts[0][0] || '';
  const last = parts.length > 1 ? parts[parts.length - 1][0] : '';
  return (first + last).toUpperCase();
}

// Sign-in buttons for visitors; the account chip once signed in. `next` is where to return
// after signing in (the current page by default).
export function AccountArea({ next }) {
  const { status, user } = useAuth();
  const pathname = usePathname() || '/';
  const target = next ?? pathname;
  if (status === 'loading') return <span className={styles.placeholder} aria-hidden="true" />;
  if (status === 'signed-in' && user) {
    return (
      <Link
        href="/account"
        className={styles.chip}
        aria-label={`Your account (${user.name})`}
        aria-current={pathname === '/account' ? 'page' : undefined}
      >
        <span className={styles.avatar} aria-hidden="true">{initials(user.name)}</span>
        <span className={styles.chipName}>{user.name}</span>
      </Link>
    );
  }
  return (
    <div className={styles.actions}>
      <Link href={loginHref(target)} className={styles.buttonQuietSmall}>Sign in</Link>
      <Link href={signupHref(target)} className={`${styles.buttonSmall} ${styles.hideNarrow}`}>Create account</Link>
    </div>
  );
}

// The bar at the top of every InstantNodes page except the lab workspace. `contained` lines
// it up with the home page's content column; `children` go to the right, before the account.
export default function SiteHeader({ contained = false, sticky = false, className = '', next, showAccount = true, children }) {
  const pathname = usePathname() || '/';
  return (
    <header className={`${styles.bar} ${sticky ? styles.barSticky : ''} ${className}`}>
      <div className={`${styles.inner} ${contained ? styles.innerContained : ''}`}>
        <Logo />
        <nav className={styles.nav} aria-label="Main">
          {NAV.map(item => (
            <Link
              key={item.href}
              href={item.href}
              className={`${styles.navLink} ${item.narrow === false ? styles.hideNarrow : ''}`}
              aria-current={item.current?.(pathname) ? 'page' : undefined}
            >
              {item.label}
            </Link>
          ))}
        </nav>
        <div className={styles.right}>
          {children}
          {showAccount && <AccountArea next={next} />}
        </div>
      </div>
    </header>
  );
}
