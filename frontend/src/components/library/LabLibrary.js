"use client";

// The lab library (/labs): lab list, lab briefing with the real topology, and a short guide.
// Progress comes from the signed-in account. Design rules: .kiro/skills/instantnodes-ui.

import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { Clock, Search, SquareTerminal, X } from 'lucide-react';
import { api } from '@/lib/api';
import { classifyNode } from '@/lib/nodeClassification';
import { useAuth } from '@/components/auth/AuthProvider';
import { loginHref, signupHref } from '@/lib/authLinks';
import SiteHeader from '@/components/site/SiteHeader';
import TopologyRenderer from '@/components/topologies/TopologyRenderer';
import styles from './library.module.css';

const LEVEL_RANK = { beginner: 1, intermediate: 2, advanced: 3 };
const STATUS_TEXT = { completed: 'Completed', progress: 'In progress', new: 'Not started' };
const SERVER_TEXT = {
  connecting: 'Connecting to the lab server',
  online: 'Lab server online',
  offline: 'Lab server offline',
};
const KIND_LABEL = { router: 'router', switch: 'switch', host: 'PC' };
const MAX_COMMANDS = 5;
const SINGLE_COLUMN = '(max-width: 859px)';
const NO_PROGRESS = { bySlug: {}, sessionSlug: null };

const STEPS = [
  {
    title: 'Open a lab and press Start',
    text: 'The routers, switches and PCs boot on the lab server.',
  },
  {
    title: 'Configure from the console',
    text: 'Pick a device to open its console and type IOS commands. ? help and Tab completion work as on real equipment.',
  },
  {
    title: 'Grade your work',
    text: 'Each task is checked against the running configuration, the device state and connectivity. A task that fails says what is missing.',
  },
];

const SIMULATED = ['VLANs', '802.1Q trunks', 'Inter-VLAN routing', 'OSPF', 'DHCP', 'NTP', 'SSH', 'LACP EtherChannel'];

// "Lab 03 — NTP & Clock Synchronization" -> { number: "03", name: "NTP & Clock Synchronization" }
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

function levelOf(lab) {
  const name = String(lab?.difficulty || 'Beginner');
  return { name, rank: LEVEL_RANK[name.toLowerCase()] || 1 };
}

// GET /api/progress -> per-lab records and the slug of the lab running now.
function toProgress(payload) {
  return {
    bySlug: payload?.labs && typeof payload.labs === 'object' ? payload.labs : {},
    sessionSlug: payload?.active_session?.lab_slug || null,
  };
}

function statusOf(slug, progress) {
  if (progress.bySlug[slug]?.completed) return 'completed';
  if (progress.sessionSlug === slug) return 'progress';
  return 'new';
}

// The running lab first, then the first lab not completed yet, then the first lab.
function pickInitial(list, progress) {
  if (progress.sessionSlug && list.some(lab => lab.slug === progress.sessionSlug)) return progress.sessionSlug;
  return (list.find(lab => !progress.bySlug[lab.slug]?.completed) || list[0])?.slug || null;
}

function LevelBars({ rank }) {
  return (
    <span className={styles.bars} data-level={rank} aria-hidden="true"><i /><i /><i /></span>
  );
}

// 16px device glyphs drawn like the topology icons: cylinder router, slab switch, monitor PC.
function DeviceGlyph({ kind }) {
  const common = {
    className: styles.glyph, width: 16, height: 16, viewBox: '0 0 16 16', fill: 'none',
    stroke: 'currentColor', strokeWidth: 1.2, strokeLinecap: 'round', strokeLinejoin: 'round',
    'aria-hidden': true,
  };
  if (kind === 'switch') {
    return (
      <svg {...common}>
        <rect x="1.5" y="4.5" width="13" height="7" rx="1.2" />
        <path d="M4.5 7h6.5M9.6 5.9 11 7 9.6 8.1M11.5 9H5M6.4 7.9 5 9l1.4 1.1" strokeWidth="1" />
      </svg>
    );
  }
  if (kind === 'host') {
    return (
      <svg {...common}>
        <rect x="2" y="2.5" width="12" height="8.5" rx="1.2" />
        <path d="M6 13.5h4M8 11v2.5" />
      </svg>
    );
  }
  return (
    <svg {...common}>
      <path d="M2 6.2v3.6c0 1.4 2.7 2.6 6 2.6s6-1.2 6-2.6V6.2" />
      <ellipse cx="8" cy="6.2" rx="6" ry="2.5" />
      <path d="M6.2 6.2h3.6M8 5.1v2.2" strokeWidth="1" />
    </svg>
  );
}

// One RJ45-style port per lab; its LED shows the lab's status.
function PortStrip({ labs, progress }) {
  return (
    <div className={styles.ports} aria-hidden="true">
      {labs.map(lab => {
        const { number, name } = splitTitle(lab.title);
        const state = statusOf(lab.slug, progress);
        return (
          <span
            key={lab.slug}
            className={styles.port}
            data-state={state}
            title={`${number ? `Lab ${number}: ` : ''}${name} (${STATUS_TEXT[state].toLowerCase()})`}
          />
        );
      })}
    </div>
  );
}

function LabRow({ lab, state, selected, focusable, onSelect }) {
  const { number, name } = splitTitle(lab.title);
  const level = levelOf(lab);
  return (
    <button
      type="button"
      role="tab"
      id={`lab-tab-${lab.slug}`}
      data-slug={lab.slug}
      aria-selected={selected}
      aria-controls="lab-briefing"
      tabIndex={focusable ? 0 : -1}
      className={styles.row}
      onClick={() => onSelect(lab.slug, true)}
    >
      <span className={`${styles.led} ${styles.rowLed}`} data-state={state} aria-hidden="true" />
      <span className={styles.rowNumber}>{number || '--'}</span>
      <span className={styles.rowText}>
        <span className={styles.rowTitle}>{name}</span>
        <span className={styles.rowMeta}>
          <span className={styles.rowTopic}>{lab.topic}</span>
          <LevelBars rank={level.rank} />
          <span className={styles.srOnly}>{level.name}</span>
          <span className={styles.rowTime}>{lab.estimated_time_minutes} min</span>
        </span>
        <span className={styles.srOnly}>{STATUS_TEXT[state]}</span>
      </span>
    </button>
  );
}

function DevicesStrip({ nodes, onHoverNode }) {
  return (
    <div className={styles.devices}>
      <span className={styles.devicesLabel}>{nodes.length} {nodes.length === 1 ? 'device' : 'devices'}</span>
      <ul className={styles.deviceList}>
        {nodes.map(node => {
          const kind = classifyNode(node);
          return (
            <li
              key={node.name}
              className={styles.device}
              title={`${node.name}, ${KIND_LABEL[kind]}`}
              onMouseEnter={() => onHoverNode(node.name)}
              onMouseLeave={() => onHoverNode(null)}
            >
              <DeviceGlyph kind={kind} />
              {node.name}
              <span className={styles.srOnly}>{`, ${KIND_LABEL[kind]}`}</span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function Briefing({ lab, state, record, signedIn, detail, hoverNode, onHoverNode, onRetryDetail }) {
  const { number, name } = splitTitle(lab.title);
  const level = levelOf(lab);
  const data = detail?.state === 'ready' ? detail.data : null;
  const nodes = Array.isArray(data?.nodes) ? data.nodes : [];
  const tasks = Array.isArray(data?.tasks) ? data.tasks : [];
  const prerequisites = Array.isArray(data?.prerequisites) ? data.prerequisites : [];
  const commands = Array.isArray(data?.command_reference) ? data.command_reference : [];
  const objective = String(lab.description || '').trim();
  const labName = number ? `Lab ${number}` : 'lab';
  const labPath = `/labs/${lab.slug}`;
  const deviceNames = nodes.map(node => node.name).join(', ');
  const best = record && record.attempts > 0 && !record.completed ? Math.floor(record.best_percentage || 0) : null;

  return (
    <div className={styles.swap}>
      <div className={styles.briefHead}>
        <div className={styles.plate} aria-hidden="true">
          <small>Lab</small>
          <strong>{number || '--'}</strong>
        </div>
        <h2 id="lab-brief-title" className={styles.briefTitle}>
          {number && <span className={styles.srOnly}>{`Lab ${number}: `}</span>}
          {name}
        </h2>
        <div className={styles.briefMeta}>
          <span className={styles.topicChip}>{lab.topic}</span>
          <span className={styles.metaItem}><LevelBars rank={level.rank} />{level.name}</span>
          <span className={styles.metaItem}><Clock size={14} aria-hidden="true" />{lab.estimated_time_minutes} min</span>
          {signedIn && (
            <span className={styles.metaItem}>
              <span className={styles.led} data-state={state} aria-hidden="true" />
              {STATUS_TEXT[state]}
            </span>
          )}
          {best !== null && <span className={styles.metaItem}>{`Best score ${best}%`}</span>}
        </div>
        {signedIn ? (
          <Link href={labPath} className={`${styles.button} ${styles.briefAction}`}>
            <SquareTerminal size={16} aria-hidden="true" />
            {`${state === 'progress' ? 'Resume' : 'Open'} ${labName}`}
          </Link>
        ) : (
          <Link href={loginHref(labPath)} className={`${styles.button} ${styles.briefAction}`}>
            {`Sign in to open ${labName}`}
          </Link>
        )}
      </div>

      {objective && <p className={styles.objective}>{objective}</p>}

      <div
        className={styles.bench}
        role="img"
        aria-label={`Topology of ${name}${deviceNames ? `: ${deviceNames}` : ''}`}
      >
        <div className={styles.benchInner}>
          <TopologyRenderer slug={lab.slug} activeNode={hoverNode} />
        </div>
      </div>

      {data && <DevicesStrip nodes={nodes} onHoverNode={onHoverNode} />}
      {!detail && (
        <div className={styles.devices} aria-hidden="true">
          <span className={styles.deviceSkel} />
          <span className={styles.deviceSkel} />
          <span className={styles.deviceSkel} />
        </div>
      )}

      <div className={styles.briefBody}>
        {detail?.state === 'error' && (
          <div className={styles.inlineNote} role="alert">
            <span>The tasks for this lab could not be loaded.</span>
            <button type="button" className={styles.buttonQuiet} onClick={onRetryDetail}>Try again</button>
          </div>
        )}

        {!detail && (
          <>
            <div className={styles.skelLines} aria-hidden="true"><span /><span /><span /><span /></div>
            <div className={styles.skelLines} aria-hidden="true"><span /><span /><span /></div>
          </>
        )}

        {data && (
          <>
            <section aria-labelledby="lab-tasks-title">
              <h3 id="lab-tasks-title" className={styles.subTitle}>Tasks</h3>
              <ol className={styles.tasks}>
                {tasks.map((task, index) => (
                  <li key={task.id ?? index}>
                    <span className={styles.taskNo} aria-hidden="true">{index + 1}</span>
                    <span>{task.description}</span>
                  </li>
                ))}
              </ol>
            </section>
            <div>
              {prerequisites.length > 0 && (
                <section aria-labelledby="lab-prereq-title">
                  <h3 id="lab-prereq-title" className={styles.subTitle}>Before you start</h3>
                  <ul className={styles.prereqs}>
                    {prerequisites.map(item => <li key={item}>{item}</li>)}
                  </ul>
                </section>
              )}
              {commands.length > 0 && (
                <section aria-labelledby="lab-commands-title">
                  <h3 id="lab-commands-title" className={styles.subTitle}>Commands you’ll use</h3>
                  <ul className={styles.commands}>
                    {commands.slice(0, MAX_COMMANDS).map(entry => (
                      <li key={entry.command}>
                        <code>{entry.command}</code>
                        <span>{entry.description}</span>
                      </li>
                    ))}
                  </ul>
                  {commands.length > MAX_COMMANDS && (
                    <p className={styles.more}>
                      {`${commands.length - MAX_COMMANDS} more in the lab’s command reference.`}
                    </p>
                  )}
                </section>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function BriefingSkeleton() {
  return (
    <div aria-hidden="true">
      <div className={styles.briefHead}>
        <div className={styles.plate} />
        <span className={`${styles.skel} ${styles.skelTitle}`} />
        <span className={`${styles.skel} ${styles.skelMeta}`} />
      </div>
      <div className={styles.bench} />
    </div>
  );
}

function AboutPanel({ signedOut }) {
  return (
    <aside className={`${styles.panel} ${styles.aside}`} aria-label="About the simulator">
      <div className={styles.asideInner}>
        {signedOut && (
          <section className={styles.asideSection} aria-labelledby="account-title">
            <h2 id="account-title" className={styles.panelTitle}>Keep your progress</h2>
            <p className={styles.asideText}>
              Create an account to open labs. It keeps your completed labs, best scores and the lab
              you are working on, on any device.
            </p>
            <div className={styles.asideActions}>
              <Link href={signupHref('/labs')} className={styles.button}>Create account</Link>
              <Link href={loginHref('/labs')} className={styles.buttonQuiet}>Sign in</Link>
            </div>
          </section>
        )}
        <section className={styles.asideSection} aria-labelledby="how-title">
          <h2 id="how-title" className={styles.panelTitle}>How labs work</h2>
          <ol className={styles.steps}>
            {STEPS.map((step, index) => (
              <li key={step.title}>
                <span className={styles.stepNo} aria-hidden="true">{index + 1}</span>
                <div>
                  <strong className={styles.stepTitle}>{step.title}</strong>
                  <p>{step.text}</p>
                </div>
              </li>
            ))}
          </ol>
        </section>
        <section className={styles.asideSection} aria-labelledby="sim-title">
          <h2 id="sim-title" className={styles.panelTitle}>What’s simulated</h2>
          <p className={styles.asideText}>
            Routers and switches run more than 300 IOS commands, with ? help, Tab completion and
            abbreviations. PCs have a host console with ip, ping and trace.
          </p>
          <ul className={styles.chips}>
            {SIMULATED.map(item => <li key={item} className={styles.chip}>{item}</li>)}
          </ul>
        </section>
        <p className={styles.legal}>
          Cisco, Cisco IOS and CCNA are trademarks of Cisco Systems, Inc. InstantNodes is not
          affiliated with Cisco.
        </p>
      </div>
    </aside>
  );
}

export default function LabLibrary({ initialSlug = null }) {
  const auth = useAuth();
  const [labs, setLabs] = useState([]);
  const [loadState, setLoadState] = useState('loading');
  const [query, setQuery] = useState('');
  // ?lab=<slug> (from the home page) preselects a lab.
  const [chosenSlug, setChosenSlug] = useState(initialSlug);
  const [details, setDetails] = useState({});
  const [hoverNode, setHoverNode] = useState(null);
  // The progress of the account it was loaded for; another account's is never shown.
  const [loadedProgress, setLoadedProgress] = useState(null);

  // State changes happen in the promise callbacks only, so the mount effect can call this directly.
  const fetchLabs = useCallback(() => {
    api.getLabs()
      .then(fetched => {
        setLabs((Array.isArray(fetched) ? [...fetched] : []).sort(byLabNumber));
        setLoadState('ready');
      })
      .catch(error => {
        console.error(error);
        setLoadState('error');
      });
  }, []);

  useEffect(() => { fetchLabs(); }, [fetchLabs]);

  const userId = auth.status === 'signed-in' ? auth.user?.id : null;
  useEffect(() => {
    if (userId == null) return undefined;
    let cancelled = false;
    api.getProgress()
      .then(payload => { if (!cancelled) setLoadedProgress({ userId, progress: toProgress(payload) }); })
      .catch(error => {
        console.error(error);
        if (!cancelled) setLoadedProgress({ userId, progress: NO_PROGRESS });
      });
    return () => { cancelled = true; };
  }, [userId]);

  const signedIn = userId != null;
  const progress = signedIn && loadedProgress?.userId === userId ? loadedProgress.progress : NO_PROGRESS;
  const progressReady = auth.status !== 'loading' && (!signedIn || loadedProgress?.userId === userId);
  const ready = loadState === 'ready' && progressReady;

  // Until the user picks a lab, show the running one, else the first unfinished one.
  const selectedSlug = ready
    ? (labs.some(lab => lab.slug === chosenSlug) ? chosenSlug : pickInitial(labs, progress))
    : null;

  // Lab details (tasks, devices, commands) are fetched once per lab, when it is first shown.
  useEffect(() => {
    if (!selectedSlug || details[selectedSlug]) return undefined;
    let cancelled = false;
    api.getLab(selectedSlug)
      .then(data => {
        if (!cancelled) setDetails(previous => ({ ...previous, [selectedSlug]: { state: 'ready', data } }));
      })
      .catch(error => {
        console.error(error);
        if (!cancelled) setDetails(previous => ({ ...previous, [selectedSlug]: { state: 'error' } }));
      });
    return () => { cancelled = true; };
  }, [selectedSlug, details]);

  const retryLabs = () => {
    setLoadState('loading');
    fetchLabs();
  };

  const retryDetail = slug => {
    setDetails(previous => {
      const next = { ...previous };
      delete next[slug];
      return next;
    });
  };

  const selectLab = (slug, reveal = false) => {
    setChosenSlug(slug);
    setHoverNode(null);
    // In the single-column layout the briefing sits below the list: bring it into view.
    if (reveal && window.matchMedia(SINGLE_COLUMN).matches) {
      const smooth = !window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      document.getElementById('lab-briefing')?.scrollIntoView({ behavior: smooth ? 'smooth' : 'auto', block: 'start' });
    }
  };

  // Arrow keys, Home and End move through the lab list (vertical tabs).
  const onListKeyDown = event => {
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
    const tabs = [...event.currentTarget.querySelectorAll('[role="tab"]')];
    if (tabs.length === 0) return;
    event.preventDefault();
    const current = tabs.indexOf(document.activeElement);
    let next = 0;
    if (event.key === 'ArrowDown') next = current < 0 ? 0 : (current + 1) % tabs.length;
    if (event.key === 'ArrowUp') next = current < 0 ? tabs.length - 1 : (current - 1 + tabs.length) % tabs.length;
    if (event.key === 'End') next = tabs.length - 1;
    tabs[next].focus();
    selectLab(tabs[next].dataset.slug);
  };

  const visibleLabs = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return labs;
    return labs.filter(lab => [lab.title, lab.topic, lab.difficulty, lab.description]
      .some(value => String(value || '').toLowerCase().includes(needle)));
  }, [labs, query]);

  const selectedLab = labs.find(lab => lab.slug === selectedSlug) || null;
  const focusSlug = visibleLabs.some(lab => lab.slug === selectedSlug) ? selectedSlug : visibleLabs[0]?.slug;
  const doneCount = labs.filter(lab => progress.bySlug[lab.slug]?.completed).length;
  const serverState = { loading: 'connecting', ready: 'online', error: 'offline' }[loadState];
  const signedOut = auth.status === 'signed-out' || auth.status === 'offline';

  return (
    <div className={styles.page}>
      <SiteHeader>
        <span className={styles.status} role="status">
          <span className={styles.led} data-state={serverState} aria-hidden="true" />
          <span className={styles.statusText}>{SERVER_TEXT[serverState]}</span>
        </span>
      </SiteHeader>

      <div className={styles.frame}>
        <section className={`${styles.panel} ${styles.library}`} aria-labelledby="labs-title">
          <div className={styles.libraryHead}>
            <div className={styles.titleRow}>
              <h1 id="labs-title" className={styles.panelTitle}>Labs</h1>
              {ready && labs.length > 0 && signedIn && (
                <span className={styles.progressText}>{`${doneCount} of ${labs.length} completed`}</span>
              )}
              {ready && labs.length > 0 && signedOut && (
                <Link href={loginHref('/labs')} className={styles.progressLink}>Sign in to track progress</Link>
              )}
            </div>
            {ready && labs.length > 0 && <PortStrip labs={labs} progress={progress} />}
            <div className={styles.search}>
              <Search size={15} className={styles.searchIcon} aria-hidden="true" />
              <input
                type="search"
                className={styles.searchInput}
                placeholder="Search labs"
                aria-label="Search labs"
                value={query}
                disabled={!ready}
                onChange={event => setQuery(event.target.value)}
              />
              {query && (
                <button type="button" className={styles.searchClear} onClick={() => setQuery('')} aria-label="Clear search">
                  <X size={14} aria-hidden="true" />
                </button>
              )}
            </div>
          </div>

          {!ready && loadState !== 'error' && (
            <div className={styles.skeletonList} aria-hidden="true">
              {[0, 1, 2, 3, 4, 5].map(key => (
                <div key={key} className={styles.skeletonRow}><span className={styles.skel} /><span className={styles.skel} /></div>
              ))}
            </div>
          )}

          {loadState === 'error' && (
            <p className={styles.listNote}>The labs appear here once the lab server responds.</p>
          )}

          {ready && labs.length === 0 && (
            <p className={styles.listNote}>No labs are installed on the lab server.</p>
          )}

          {ready && labs.length > 0 && visibleLabs.length === 0 && (
            <div className={styles.listNote}>
              <p>{`No labs match “${query.trim()}”.`}</p>
              <button type="button" className={styles.linkButton} onClick={() => setQuery('')}>Clear search</button>
            </div>
          )}

          {ready && visibleLabs.length > 0 && (
            <div
              role="tablist"
              aria-orientation="vertical"
              aria-labelledby="labs-title"
              className={styles.list}
              onKeyDown={onListKeyDown}
            >
              {visibleLabs.map(lab => (
                <LabRow
                  key={lab.slug}
                  lab={lab}
                  state={statusOf(lab.slug, progress)}
                  selected={lab.slug === selectedSlug}
                  focusable={lab.slug === focusSlug}
                  onSelect={selectLab}
                />
              ))}
            </div>
          )}
        </section>

        <div className={styles.main}>
          <section
            id="lab-briefing"
            className={`${styles.panel} ${styles.briefing}`}
            role={ready && selectedLab ? 'tabpanel' : undefined}
            aria-labelledby={ready && selectedLab ? 'lab-brief-title' : undefined}
          >
            {!ready && loadState !== 'error' && <BriefingSkeleton />}

            {loadState === 'error' && (
              <div className={styles.notice} role="alert">
                <h2 className={styles.noticeTitle}>The lab server did not respond</h2>
                <p>InstantNodes loads its labs from the lab server. Check that it is running, then try again.</p>
                <button type="button" className={styles.button} onClick={retryLabs}>Try again</button>
              </div>
            )}

            {ready && !selectedLab && (
              <div className={styles.notice}>
                <h2 className={styles.noticeTitle}>No labs yet</h2>
                <p>Add a lab folder with a lab.yaml file to the labs directory, then restart the lab server.</p>
              </div>
            )}

            {ready && selectedLab && (
              <Briefing
                key={selectedLab.slug}
                lab={selectedLab}
                state={statusOf(selectedLab.slug, progress)}
                record={progress.bySlug[selectedLab.slug]}
                signedIn={signedIn}
                detail={details[selectedLab.slug]}
                hoverNode={hoverNode}
                onHoverNode={setHoverNode}
                onRetryDetail={() => retryDetail(selectedLab.slug)}
              />
            )}
          </section>

          <AboutPanel signedOut={signedOut} />
        </div>
      </div>
    </div>
  );
}
