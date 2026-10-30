import React, { useState, useRef, useEffect } from 'react';
import { useRouter } from 'next/navigation';

const CheckIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
);
const CrossIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
);
const CircleIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/></svg>
);

function plural(count, word) {
  return `${count} ${word}${count === 1 ? '' : 's'}`;
}

// What the grader found missing or wrong for one task (see grading_engine.py).
function GradeFindings({ findings }) {
  if (!findings?.length) return null;
  return (
    <ul className="nx-findings">
      {findings.map((finding, index) => (
        <li key={index} className={`nx-finding nx-finding-${finding.kind || 'config'}`}>
          <div>
            {finding.node && <span className="nx-finding-node">{finding.node}</span>}
            {finding.title && <strong className="nx-finding-title">{finding.title}: </strong>}
            <span>{finding.message}</span>
          </div>
          {finding.expected?.length > 0 && (
            <>
              <div className="nx-finding-label">Expected</div>
              <pre className="nx-finding-code">{finding.expected.join('\n')}</pre>
            </>
          )}
          {finding.found?.length > 0 && (
            <>
              <div className="nx-finding-label">Currently configured</div>
              <pre className="nx-finding-code is-found">{finding.found.join('\n')}</pre>
            </>
          )}
        </li>
      ))}
    </ul>
  );
}

function TaskGradeStatus({ result, labPassed }) {
  if (!result) return null;
  if (labPassed || result.passed) {
    return <div className="nx-task-status is-passed">Complete</div>;
  }
  if (!result.graded) {
    return <div className="nx-task-status">Not graded</div>;
  }
  const issues = result.findings?.length || 0;
  return (
    <div className="nx-task-status is-failed">
      Not complete{issues ? ` · ${plural(issues, 'issue')}` : ''}
    </div>
  );
}

function GradeSummary({ report }) {
  const summary = report.summary;
  if (report.passed) {
    return (
      <div className="nx-grade-summary is-passed">
        <strong>All tasks complete.</strong> Score {report.percentage}%.
      </div>
    );
  }
  if (!summary) {
    return (
      <div className="nx-grade-summary is-failed">
        <strong>Not complete yet.</strong> Your configuration does not match the solution.
      </div>
    );
  }
  return (
    <div className="nx-grade-summary is-failed">
      <strong>Score {report.percentage}%.</strong>{' '}
      {summary.tasks_passed} of {plural(summary.tasks_graded, 'graded task')} complete.
      Open a task marked with a cross to see what is missing.
    </div>
  );
}

export default function LabSidebar({ 
  lab, allLabs, slug,
  gradeReport, isGrading,
  visibleAnswers, setVisibleAnswers
}) {
  const router = useRouter();
  
  const [sidebarTopHeight, setSidebarTopHeight] = useState(30);
  const [isCommandSummaryOpen, setIsCommandSummaryOpen] = useState(false);
  const [isLabContentOpen, setIsLabContentOpen] = useState(true);
  const [isLabInstructionsOpen, setIsLabInstructionsOpen] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  
  const isSidebarDragging = useRef(false);
  const sidebarRef = useRef(null);

  const handleSidebarDragStart = (e) => {
    e.preventDefault();
    isSidebarDragging.current = true;
    document.body.style.cursor = 'row-resize';
    document.body.style.userSelect = 'none';
  };

  useEffect(() => {
    const handleMouseMove = (e) => {
      if (!isSidebarDragging.current || !sidebarRef.current) return;
      const rect = sidebarRef.current.getBoundingClientRect();
      const newHeight = ((e.clientY - rect.top) / rect.height) * 100;
      if (newHeight >= 15 && newHeight <= 85) {
        setSidebarTopHeight(newHeight);
      }
    };
    const handleMouseUp = () => {
      if (isSidebarDragging.current) {
        isSidebarDragging.current = false;
        document.body.style.cursor = '';
        document.body.style.userSelect = '';
      }
    };
    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
  }, []);

  const sortedLabs = [...allLabs].sort((a, b) => a.title.localeCompare(b.title));

  const filteredLabs = searchQuery.trim()
    ? sortedLabs.filter(l => l.title.toLowerCase().includes(searchQuery.toLowerCase()))
    : sortedLabs;

  const taskResults = new Map(
    (gradeReport?.tasks || [])
      .filter(result => result.id !== null && result.id !== undefined)
      .map(result => [String(result.id), result])
  );
  const otherRequirements = (gradeReport?.tasks || []).find(
    result => (result.id === null || result.id === undefined) && result.graded && !result.passed
  );
  const labPassed = Boolean(gradeReport?.passed);

  return (
    <aside className="nx-sidebar-left nx-card" ref={sidebarRef}>
      {/* Top Section */}
      <div style={{ flex: isLabContentOpen ? (isLabInstructionsOpen ? `0 0 ${sidebarTopHeight}%` : '1') : '0 0 auto', display: 'flex', flexDirection: 'column', overflow: 'hidden', transition: 'flex 0.2s ease-out' }}>
        <div className="nx-section-header" style={{ flexShrink: 0, cursor: 'pointer' }} onClick={() => setIsLabContentOpen(!isLabContentOpen)}>
          <span className="nx-section-title">Lab Content</span>
          <svg className="nx-section-chevron" style={{ transform: isLabContentOpen ? 'none' : 'rotate(-90deg)', transition: 'transform 0.2s ease-out' }} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
        </div>
        {isLabContentOpen && (
          <>
            <div className="nx-search-wrap" style={{ flexShrink: 0 }}>
              <div className="nx-search-inner">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#9ca3af" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
                <input
                  type="text"
                  placeholder="Search Labs..."
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                />
              </div>
            </div>
            <div style={{ flex: 1, overflowY: 'auto' }}>
              {filteredLabs.length === 0 ? (
                <div style={{ padding: '12px 16px', color: 'var(--text-muted)', fontSize: '13px' }}>No labs found.</div>
              ) : (
                filteredLabs.map(l => (
                  <div
                    key={l.slug}
                    className={`nx-tree-item ${l.slug === slug ? 'selected' : ''}`}
                    onClick={() => router.push(`/labs/${l.slug}`)}
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" style={{ flexShrink: 0, marginRight: '4px', opacity: 0.8 }}><path d="m7 11 2-2-2-2"/><path d="M11 13h4"/><rect width="18" height="18" x="3" y="3" rx="2" ry="2"/></svg>
                    <span style={{ fontSize: '13px', letterSpacing: '0.2px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{l.title}</span>
                  </div>
                ))
              )}
            </div>
          </>
        )}
      </div>

      {/* Resizer Handle */}
      {isLabContentOpen && isLabInstructionsOpen && (
        <div 
          onMouseDown={handleSidebarDragStart}
          style={{ height: '4px', background: 'var(--bg-card)', borderTop: '1px solid var(--border)', borderBottom: '1px solid var(--border)', cursor: 'row-resize', flexShrink: 0, zIndex: 10 }}
        />
      )}

      {/* Bottom Section */}
      <div style={{ flex: isLabInstructionsOpen ? '1' : '0 0 auto', display: 'flex', flexDirection: 'column', overflow: 'hidden', transition: 'flex 0.2s ease-out' }}>
        <div className="nx-section-header" style={{ flexShrink: 0, marginTop: 0, cursor: 'pointer' }} onClick={() => setIsLabInstructionsOpen(!isLabInstructionsOpen)}>
          <span className="nx-section-title">Lab Instructions</span>
          <svg className="nx-section-chevron" style={{ transform: isLabInstructionsOpen ? 'none' : 'rotate(-90deg)', transition: 'transform 0.2s ease-out' }} width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
        </div>

        {isLabInstructionsOpen && (
          <div className="nx-instructions-body" style={{ flex: 1, overflowY: 'auto', padding: '16px' }}>
            <div className="nx-timeline">
              {lab?.tasks?.map((task, index) => {
                const result = taskResults.get(String(task.id));
                const isPassed = labPassed || Boolean(result?.passed);
                const isFailed = !labPassed && Boolean(result?.graded) && !result?.passed;
                const isCurrent = visibleAnswers[task.id] || (index === 0 && Object.keys(visibleAnswers).length === 0);
                const statusClass = isPassed ? 'is-completed' : isFailed ? 'is-failed' : (isCurrent ? 'is-current' : 'is-pending');
                
                return (
                  <div key={task.id} className={`nx-timeline-step ${statusClass}`} onClick={() => setVisibleAnswers({ [task.id]: true })} style={{ cursor: 'pointer' }}>
                    <div className="nx-timeline-node">
                      {isPassed ? <CheckIcon /> : isFailed ? <CrossIcon /> : <CircleIcon />}
                    </div>
                    <div className="nx-timeline-content">
                      <div className="nx-timeline-title">{task.description}</div>
                      <TaskGradeStatus result={result} labPassed={labPassed} />
                      {isCurrent && (
                        <div className="nx-timeline-desc" style={{ whiteSpace: 'pre-line', marginTop: '8px' }}>
                          {task.instructions}
                        </div>
                      )}
                      {isCurrent && isFailed && <GradeFindings findings={result.findings} />}
                    </div>
                  </div>
                );
              })}

              <div className={`nx-timeline-step ${isGrading || gradeReport ? 'is-current' : 'is-pending'}`}>
                <div className="nx-timeline-node">
                  {gradeReport && gradeReport.passed ? (
                    <CheckIcon />
                  ) : gradeReport && !gradeReport.passed ? (
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                  ) : (
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
                  )}
                </div>
                <div className="nx-timeline-content">
                  <div className="nx-timeline-title">Verify Configuration</div>
                  <div className="nx-timeline-desc">Click Grade to check your work. Each task then shows what is still missing.</div>
                  {gradeReport && <GradeSummary report={gradeReport} />}
                  {otherRequirements && (
                    <>
                      <div className="nx-task-status is-failed" style={{ marginTop: '10px' }}>{otherRequirements.description}</div>
                      <GradeFindings findings={otherRequirements.findings} />
                    </>
                  )}
                </div>
              </div>
            </div>

            <div style={{ borderTop: '1px solid var(--border)', paddingTop: '16px' }}>
              <button className="nx-command-summary-btn" onClick={() => setIsCommandSummaryOpen(!isCommandSummaryOpen)}>
                {isCommandSummaryOpen ? (
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="6 9 12 15 18 9"/></svg>
                ) : (
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
                )}
                View Command Summary
              </button>

              {isCommandSummaryOpen && (
                <div style={{ marginTop: '12px' }}>
                  {lab?.command_reference ? lab.command_reference.map((cmd, i) => (
                    <div className="nx-command-block" key={i}>
                      <div className="nx-command-text">{cmd.command}</div>
                      <div className="nx-command-desc">{cmd.description}</div>
                    </div>
                  )) : (
                    <div className="nx-command-block">
                       <div className="nx-command-desc">No commands available.</div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </aside>
  );
}
