import React from 'react';
import Link from 'next/link';
import Logo from '@/components/site/Logo';
import { AccountArea } from '@/components/site/SiteHeader';
import siteStyles from '@/components/site/site.module.css';

export default function TopNav({
  session, isBooting, labTimer, gradeReport, isGrading,
  handleStart, handleStop, handleGrade, setShowResetModal
}) {
  const formatTime = (totalSeconds) => {
    const h = Math.floor(totalSeconds / 3600);
    const m = Math.floor((totalSeconds % 3600) / 60).toString().padStart(2, '0');
    const s = (totalSeconds % 60).toString().padStart(2, '0');
    if (h > 0) {
      return `${h.toString().padStart(2, '0')}:${m}:${s}`;
    }
    return `${m}:${s}`;
  };

  return (
    <header className="nx-header">
      {/* Left: logo (home page) and the way back to the lab library */}
      <div className="nx-brand">
        <Logo />
        <nav className={siteStyles.workspaceNav} aria-label="Main">
          <Link href="/labs" className={siteStyles.navLink}>Labs</Link>
        </nav>
      </div>

      {/* Right: controls */}
      <div className="nx-toolbar">
        {session ? (
          <div className="nx-status-pill" style={{ color: isBooting ? 'var(--warning, #f59e0b)' : 'var(--green)' }}>
            <div className="nx-status-dot" style={{ background: isBooting ? 'var(--warning, #f59e0b)' : 'var(--green)' }} />
            {isBooting ? 'Booting...' : `Running ${formatTime(labTimer)}`}
          </div>
        ) : (
          <div className="nx-status-pill" style={{ borderColor: 'var(--border)', color: 'var(--text-muted)' }}>
            <div className="nx-status-dot" style={{ background: 'var(--text-muted)' }} />
            Stopped
          </div>
        )}

        {/* Action Button Group */}
        <div style={{ display: 'flex', gap: '8px' }}>
          
          {/* Grade */}
          <button className="nx-action-btn nx-btn-blue" onClick={handleGrade} disabled={!session || isBooting || isGrading || gradeReport?.passed} title="Grade Lab">
            {isGrading ? (
              <>
                <svg className="nx-spin" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 12a9 9 0 1 1-6.219-8.56" />
                </svg>
                Grading...
              </>
            ) : gradeReport?.passed ? (
              <>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                Graded
              </>
            ) : (
              <>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                Grade
              </>
            )}
          </button>

          {/* Play */}
          <button className="nx-icon-action-btn nx-btn-green" onClick={handleStart} disabled={!!session || isBooting} title="Start Lab">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><path d="M8 5v14l11-7z"/></svg>
          </button>

          {/* Stop */}
          <button className="nx-icon-action-btn nx-btn-red" onClick={handleStop} disabled={!session || isBooting} title="Stop Lab">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><rect x="4" y="4" width="16" height="16"/></svg>
          </button>

          {/* Refresh (Reset) */}
          <button className="nx-icon-action-btn nx-btn-gray" onClick={() => setShowResetModal(true)} disabled={!session || isBooting} title="Reset Lab">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
          </button>
        </div>

        <AccountArea />
      </div>
    </header>
  );
}
