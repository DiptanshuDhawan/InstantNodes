"use client";

import SiteHeader from '@/components/site/SiteHeader';
import TopologyRenderer from '@/components/topologies/TopologyRenderer';
import styles from './auth.module.css';

const KEEPS = [
  'Completed labs and your best score in each',
  'The lab you are working on, ready on any device',
  'A grade report every time you press Grade',
];

// Page frame for the sign-in screens: top bar, the form on the left, a lab bench on the right.
export default function AuthShell({ title, lead, children }) {
  return (
    <div className={styles.page}>
      <SiteHeader showAccount={false} />
      <div className={styles.stage}>
        <section className={styles.card} aria-labelledby="auth-title">
          <div className={styles.formSide}>
            <h1 id="auth-title" className={styles.title}>{title}</h1>
            <p className={styles.lead}>{lead}</p>
            {children}
          </div>
          <aside className={styles.benchSide} aria-label="What your account keeps">
            <div className={styles.bench} aria-hidden="true">
              <div className={styles.benchInner}>
                <TopologyRenderer slug="roas-1" />
              </div>
            </div>
            <h2 className={styles.keepsTitle}>Your account keeps</h2>
            <ul className={styles.keeps}>
              {KEEPS.map(item => <li key={item}>{item}</li>)}
            </ul>
          </aside>
        </section>
      </div>
    </div>
  );
}
