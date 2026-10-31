"use client";

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { api, apiErrorMessage } from '@/lib/api';
import { loginHref } from '@/lib/authLinks';
import { useAuth } from '@/components/auth/AuthProvider';
import PasswordField from '@/components/auth/PasswordField';
import SiteHeader, { initials } from '@/components/site/SiteHeader';
import styles from './account.module.css';

const STATUS_TEXT = { completed: 'Completed', progress: 'In progress', new: 'Not started' };

function splitTitle(title) {
  const text = String(title || '').trim();
  const match = /^Lab\s+(\d+)\s*[—–-]\s*(.+)$/u.exec(text);
  return match ? { number: match[1], name: match[2] } : { number: null, name: text };
}

function byLabNumber(a, b) {
  const left = Number(splitTitle(a.title).number ?? Number.MAX_SAFE_INTEGER);
  const right = Number(splitTitle(b.title).number ?? Number.MAX_SAFE_INTEGER);
  return left - right || String(a.title).localeCompare(String(b.title));
}

function formatDate(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return new Intl.DateTimeFormat(undefined, { day: 'numeric', month: 'short', year: 'numeric' }).format(date);
}

function ProfilePanel({ user, onSignOut, busy }) {
  return (
    <section className={`${styles.panel} ${styles.section}`} aria-labelledby="profile-title">
      <h2 id="profile-title" className={styles.panelTitle}>Profile</h2>
      <div className={styles.identity}>
        <span className={styles.avatar} aria-hidden="true">{initials(user.name)}</span>
        <div className={styles.identityText}>
          <p className={styles.name}>{user.name}</p>
          <p className={styles.email}>{user.email}</p>
        </div>
      </div>
      <dl className={styles.facts}>
        <div><dt>Member since</dt><dd>{formatDate(user.created_at) || 'Today'}</dd></div>
      </dl>
      <div className={styles.actions}>
        <button type="button" className={styles.buttonQuiet} onClick={() => onSignOut(false)} disabled={busy}>
          Sign out
        </button>
        <button type="button" className={styles.buttonQuiet} onClick={() => onSignOut(true)} disabled={busy}>
          Sign out on all devices
        </button>
      </div>
    </section>
  );
}

function PasswordPanel() {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [note, setNote] = useState(null);
  const [busy, setBusy] = useState(false);

  const onSubmit = async event => {
    event.preventDefault();
    setNote(null);
    setBusy(true);
    try {
      const { message } = await api.changePassword({ currentPassword: current, newPassword: next });
      setNote({ tone: 'ok', text: message || 'Password changed.' });
      setCurrent('');
      setNext('');
    } catch (failure) {
      setNote({ tone: 'error', text: apiErrorMessage(failure, 'The password could not be changed. Try again.') });
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className={`${styles.panel} ${styles.section}`} aria-labelledby="password-title">
      <h2 id="password-title" className={styles.panelTitle}>Change password</h2>
      <form className={styles.form} onSubmit={onSubmit} noValidate>
        <PasswordField id="current-password" label="Current password" value={current} onChange={setCurrent} autoComplete="current-password" />
        <PasswordField
          id="new-password"
          label="New password"
          value={next}
          onChange={setNext}
          autoComplete="new-password"
          minLength={8}
          hint="At least 8 characters. Your other devices are signed out when it changes."
        />
        {note && (
          <p className={styles.formNote} data-tone={note.tone} role={note.tone === 'error' ? 'alert' : 'status'}>
            {note.text}
          </p>
        )}
        <div>
          <button type="submit" className={styles.button} disabled={busy || !current || !next}>
            {busy ? 'Changing…' : 'Change password'}
          </button>
        </div>
      </form>
    </section>
  );
}

function ProgressPanel({ labs, progress, error }) {
  if (error) {
    return (
      <section className={`${styles.panel} ${styles.progress}`} aria-labelledby="progress-title">
        <div className={styles.notice} role="alert">
          <h2 id="progress-title">Your progress could not be loaded</h2>
          <p>{error}</p>
        </div>
      </section>
    );
  }
  const records = progress?.labs || {};
  const running = progress?.active_session?.lab_slug || null;
  const done = labs.filter(lab => records[lab.slug]?.completed).length;
  return (
    <section className={`${styles.panel} ${styles.progress}`} aria-labelledby="progress-title">
      <div className={styles.progressHead}>
        <div className={styles.progressTitleRow}>
          <h2 id="progress-title" className={styles.panelTitle}>Progress</h2>
          {progress && <span className={styles.summary}>{`${done} of ${labs.length} labs completed`}</span>}
        </div>
      </div>
      {!progress ? (
        <div className={styles.skeleton} aria-hidden="true"><span /><span /><span /><span /></div>
      ) : (
        <div className={styles.tableWrap}>
          <table className={styles.table}>
            <thead>
              <tr>
                <th scope="col">Lab</th>
                <th scope="col" className={styles.hideNarrow}>Status</th>
                <th scope="col">Best score</th>
                <th scope="col" className={styles.hideNarrow}>Times graded</th>
                <th scope="col" className={styles.hideNarrow}>Last graded</th>
                <th scope="col"><span className={styles.srOnly}>Action</span></th>
              </tr>
            </thead>
            <tbody>
              {labs.map(lab => {
                const { number, name } = splitTitle(lab.title);
                const record = records[lab.slug];
                const state = record?.completed ? 'completed' : running === lab.slug ? 'progress' : 'new';
                return (
                  <tr key={lab.slug}>
                    <th scope="row">
                      <span className={styles.labCell}>
                        <span className={styles.led} data-state={state} aria-hidden="true" />
                        <span className={styles.labNumber}>{number || '--'}</span>
                        <span className={styles.labName}>{name}</span>
                        <span className={styles.statusNarrow}>{`, ${STATUS_TEXT[state]}`}</span>
                      </span>
                    </th>
                    <td className={styles.hideNarrow}>{STATUS_TEXT[state]}</td>
                    <td>{record?.attempts ? `${Math.floor(record.best_percentage || 0)}%` : '–'}</td>
                    <td className={styles.hideNarrow}>{record?.attempts || 0}</td>
                    <td className={styles.hideNarrow}>{formatDate(record?.last_graded_at) || '–'}</td>
                    <td>
                      <Link href={`/labs/${lab.slug}`} className={styles.labLink}>
                        {state === 'progress' ? 'Resume' : 'Open'}
                        <span className={styles.srOnly}>{` ${number ? `Lab ${number}` : name}`}</span>
                      </Link>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

export default function AccountView() {
  const router = useRouter();
  const { status, user, signOut } = useAuth();
  const [labs, setLabs] = useState([]);
  const [progress, setProgress] = useState(null);
  const [error, setError] = useState(null);
  const [signingOut, setSigningOut] = useState(false);
  const userId = status === 'signed-in' ? user?.id : null;

  // Visitors are sent to sign in; not after signing out here, which goes home instead.
  useEffect(() => {
    if (status === 'signed-out' && !signingOut) router.replace(loginHref('/account'));
  }, [status, signingOut, router]);

  const load = useCallback(() => Promise.all([api.getLabs(), api.getProgress()])
    .then(([labList, record]) => {
      setLabs((Array.isArray(labList) ? [...labList] : []).sort(byLabNumber));
      setProgress(record);
      setError(null);
    })
    .catch(failure => setError(apiErrorMessage(failure, 'Try again in a moment.'))), []);

  useEffect(() => {
    if (userId != null) load();
  }, [userId, load]);

  const onSignOut = async everywhere => {
    setSigningOut(true);
    try {
      await signOut({ everywhere });
      router.replace('/');
    } catch (failure) {
      setError(apiErrorMessage(failure, 'Signing out did not work. Try again.'));
      setSigningOut(false);
    }
  };

  return (
    <div className={styles.page}>
      <SiteHeader />

      <div className={styles.frame}>
        <h1 className={styles.srOnly}>Your account</h1>
        {status === 'signed-in' && user ? (
          <>
            <div className={styles.side}>
              <ProfilePanel user={user} onSignOut={onSignOut} busy={signingOut} />
              <PasswordPanel />
            </div>
            <ProgressPanel labs={labs} progress={progress} error={error} />
          </>
        ) : status === 'offline' ? (
          <section className={`${styles.panel} ${styles.progress} ${styles.wide}`}>
            <div className={styles.notice} role="alert">
              <h2>The lab server did not respond</h2>
              <p>Your account is stored on the lab server. Check that it is running, then reload this page.</p>
            </div>
          </section>
        ) : (
          <section className={`${styles.panel} ${styles.progress} ${styles.wide}`} aria-hidden="true">
            <div className={styles.skeleton}><span /><span /><span /></div>
          </section>
        )}
      </div>
    </div>
  );
}
