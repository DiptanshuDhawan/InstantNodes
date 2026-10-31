"use client";

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { Clock } from 'lucide-react';
import { api } from '@/lib/api';
import styles from './landing.module.css';

const LEVEL_RANK = { beginner: 1, intermediate: 2, advanced: 3 };

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

// The catalogue on the home page; each row opens the lab library with that lab selected.
export default function LabTeaser() {
  const [labs, setLabs] = useState(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    api.getLabs()
      .then(list => { if (!cancelled) setLabs((Array.isArray(list) ? [...list] : []).sort(byLabNumber)); })
      .catch(() => { if (!cancelled) setFailed(true); });
    return () => { cancelled = true; };
  }, []);

  if (failed) {
    return <p className={styles.rackNote}>The list of labs appears here when the lab server responds.</p>;
  }
  if (!labs) {
    return (
      <div className={styles.rack} aria-hidden="true">
        {[0, 1, 2, 3, 4, 5].map(key => <div key={key} className={styles.rackSkeleton} />)}
      </div>
    );
  }
  return (
    <ul className={styles.rack}>
      {labs.map(lab => {
        const { number, name } = splitTitle(lab.title);
        const level = String(lab.difficulty || 'Beginner');
        const rank = LEVEL_RANK[level.toLowerCase()] || 1;
        return (
          <li key={lab.slug}>
            <Link href={`/labs?lab=${encodeURIComponent(lab.slug)}`} className={styles.rackRow}>
              <span className={styles.rackPlate} aria-hidden="true">{number || '--'}</span>
              <span className={styles.rackText}>
                <span className={styles.rackTitle}>
                  {number && <span className={styles.srOnly}>{`Lab ${number}: `}</span>}
                  {name}
                </span>
                <span className={styles.rackObjective}>{String(lab.description || '').trim()}</span>
              </span>
              <span className={styles.rackTopic}>{lab.topic}</span>
              <span className={styles.rackLevel}>
                <span className={styles.bars} data-level={rank} aria-hidden="true"><i /><i /><i /></span>
                {level}
              </span>
              <span className={styles.rackTime}><Clock size={14} aria-hidden="true" />{lab.estimated_time_minutes} min</span>
            </Link>
          </li>
        );
      })}
    </ul>
  );
}
