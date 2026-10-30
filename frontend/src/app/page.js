"use client";

import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import {
  ArrowRight, BookOpen, CircleCheckBig, Clock, ListChecks, Network, Play, Search,
  SquareTerminal, Zap,
} from 'lucide-react';
import { api } from '@/lib/api';
import TopologyRenderer from '@/components/topologies/TopologyRenderer';
import styles from './home.module.css';

const DIFFICULTIES = ['Beginner', 'Intermediate', 'Advanced'];
const ALL = 'All';

const TOPIC_COLORS = {
  'network fundamentals': '#38bdf8',
  'ospf': '#a78bfa',
  'ntp': '#f472b6',
  'routing & switching': '#60a5fa',
  'network access': '#2dd4bf',
};
const FALLBACK_COLORS = ['#60a5fa', '#a78bfa', '#2dd4bf', '#f472b6', '#fbbf24', '#38bdf8'];

function topicColor(topic) {
  const key = String(topic || '').toLowerCase();
  if (TOPIC_COLORS[key]) return TOPIC_COLORS[key];
  let hash = 0;
  for (const char of key) hash = (hash * 31 + char.charCodeAt(0)) >>> 0;
  return FALLBACK_COLORS[hash % FALLBACK_COLORS.length];
}

// "Lab 03 — NTP & Clock Synchronization" -> { number: "03", name: "NTP & ..." }
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

// A short IOS session for the hero terminal: [className, text] segments per line.
const TERMINAL_LINES = [
  [['tPrompt', 'R1#'], ['tCmd', 'configure terminal']],
  [['tMuted', 'Enter configuration commands, one per line.  End with CNTL/Z.']],
  [['tPrompt', 'R1(config)#'], ['tCmd', 'router ospf 1']],
  [['tPrompt', 'R1(config-router)#'], ['tCmd', 'network 192.168.1.0 0.0.0.255 area 0']],
  [['tPrompt', 'R1(config-router)#'], ['tCmd', 'end']],
  [['tLog', '*Mar  1 00:04:12.311: %OSPF-5-ADJCHG: Process 1, Nbr 192.168.1.2 on Ethernet0/0 from LOADING to FULL, Loading Done']],
  [['tPrompt', 'R1#'], ['tCmd', 'show ip ospf neighbor']],
  [['tMuted', '']],
  [['tMuted', 'Neighbor ID     Pri   State           Dead Time   Address         Interface']],
  [['tCmd', '192.168.1.2       1   '], ['tOk', 'FULL/DR'], ['tCmd', '         00:00:36    192.168.1.2     Ethernet0/0']],
  [['tPrompt', 'R1#'], ['tCmd', 'ping 192.168.1.2']],
  [['tMuted', 'Type escape sequence to abort.']],
  [['tMuted', 'Sending 5, 100-byte ICMP Echos to 192.168.1.2, timeout is 2 seconds:']],
  [['tOk', '!!!!!']],
  [['tMuted', 'Success rate is 100 percent (5/5), round-trip min/avg/max = 1/1/2 ms']],
  [['tPrompt', 'R1#'], ['cursor', '']],
];

const GRADED_TASKS = [
  'R1 interface provisioning',
  'R2 interface provisioning',
  'OSPF initialization & advertisement',
  'Adjacency verification',
];

const FEATURES = [
  {
    icon: SquareTerminal,
    title: 'A real IOS command line',
    text: 'Abbreviations, ? help, Tab completion and show output computed from the live network.',
    chips: ['show ip route', '?', 'Tab', 'do show'],
  },
  {
    icon: Network,
    title: 'Networks that behave',
    text: 'VLANs, trunks, EtherChannel, OSPF, DHCP, NTP and SSH run as protocols, so a ping fails for a real reason.',
    chips: ['802.1Q', 'LACP', 'OSPF', 'DHCP'],
  },
  {
    icon: ListChecks,
    title: 'Grading that teaches',
    text: 'Every task is checked against configuration, device state and connectivity, with what is missing and why.',
    chips: ['per-task score', 'findings'],
  },
  {
    icon: Zap,
    title: 'Nothing to install',
    text: 'Runs in your browser. No device images, no virtual machines and no setup.',
    chips: ['browser only'],
  },
];

const STEPS = [
  {
    icon: BookOpen,
    title: 'Pick a lab',
    text: 'Each lab comes with a topology, step-by-step tasks and a command reference.',
  },
  {
    icon: SquareTerminal,
    title: 'Configure the devices',
    text: "Open any device's console and type IOS commands, as you would on a real router or switch.",
  },
  {
    icon: ListChecks,
    title: 'Grade your work',
    text: 'See which tasks pass, what is missing and what is configured now. Fix it and grade again.',
  },
];

function Brand() {
  return (
    <Link href="/" className={styles.brand} aria-label="InstantNodes home">
      <span className={styles.brandTop}>INSTANT</span>
      <span className={styles.brandBottom}>
        <i className={styles.brandRule} />
        <span>NODES</span>
        <i className={styles.brandRule} />
      </span>
    </Link>
  );
}

function HeroVisual() {
  return (
    <div className={styles.visual} aria-hidden="true">
      <div className={styles.terminal}>
        <div className={styles.termBar}>
          <span className={styles.termDot} />
          <span className={styles.termDot} />
          <span className={styles.termDot} />
          <span className={styles.termTitle}>R1 · console</span>
          <span className={styles.termLive}>live</span>
        </div>
        <pre className={styles.termBody}>
          {TERMINAL_LINES.map((segments, index) => (
            <span key={index} className={styles.termLine} style={{ '--i': index }}>
              {segments.map(([kind, text], part) => (
                kind === 'cursor'
                  ? <span key={part} className={styles.cursor} />
                  : <span key={part} className={styles[kind]}>{text}</span>
              ))}
            </span>
          ))}
        </pre>
      </div>

      <div className={styles.gradeCard}>
        <div className={styles.gradeHead}>
          <div>
            <span className={styles.gradeLabel}>Grade report</span>
            <span className={styles.gradeLab}>OSPF Fundamentals</span>
          </div>
          <span className={styles.gradeScore}>100%</span>
        </div>
        <div className={styles.gradeBar}><span /></div>
        <ul className={styles.gradeTasks}>
          {GRADED_TASKS.map(task => (
            <li key={task}><CircleCheckBig size={15} />{task}</li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function LabCard({ lab, index, completed }) {
  const { number, name } = splitTitle(lab.title);
  const difficulty = lab.difficulty || 'Beginner';
  return (
    <Link
      href={`/labs/${lab.slug}`}
      className={styles.card}
      style={{ '--accent': topicColor(lab.topic), '--i': index }}
      aria-label={`${lab.title}${completed ? ' (completed)' : ''}`}
    >
      <div className={styles.cardPreview}>
        <div className={styles.cardPreviewInner}>
          <TopologyRenderer slug={lab.slug} />
        </div>
        {number && <span className={`${styles.cardBadge} ${styles.cardNumber}`}>Lab {number}</span>}
        {completed && (
          <span className={`${styles.cardBadge} ${styles.cardDone}`}>
            <CircleCheckBig size={13} /> Completed
          </span>
        )}
      </div>
      <div className={styles.cardBody}>
        <span className={styles.cardTopic}>{lab.topic}</span>
        <h3 className={styles.cardTitle}>{name}</h3>
        <p className={styles.cardDesc}>{lab.description}</p>
        <div className={styles.cardMeta}>
          <span className={styles.level} data-level={difficulty.toLowerCase()}>{difficulty}</span>
          <span className={styles.duration}><Clock size={14} /> {lab.estimated_time_minutes} min</span>
          <span className={styles.cardCta}>{completed ? 'Open lab' : 'Start lab'} <ArrowRight size={15} /></span>
        </div>
      </div>
    </Link>
  );
}

export default function Home() {
  const [labs, setLabs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [query, setQuery] = useState('');
  const [difficulty, setDifficulty] = useState(ALL);
  const [topic, setTopic] = useState(ALL);
  const [resumeSlug, setResumeSlug] = useState(null);
  const [completed, setCompleted] = useState(() => new Set());

  // State changes happen in the promise callbacks only, so the mount effect can call this directly.
  const fetchLabs = useCallback(() => {
    api.getLabs()
      .then(fetched => {
        const list = Array.isArray(fetched) ? fetched : [];
        setLabs(list);
        try {
          const done = new Set(
            list.filter(lab => localStorage.getItem(`netlabx_grade_${lab.slug}`) === '100').map(lab => lab.slug)
          );
          setCompleted(done);
          // Resume the lab with an active session, else the last lab visited.
          let slug = null;
          const session = localStorage.getItem('netlabx_session');
          if (session) {
            try { slug = JSON.parse(session)?.slug || null; } catch { slug = null; }
          }
          slug = slug || localStorage.getItem('netlabx_last_lab');
          setResumeSlug(list.some(lab => lab.slug === slug) ? slug : null);
        } catch {
          // Storage unavailable: no resume card or completion badges.
        }
      })
      .catch(error => {
        console.error(error);
        setLoadError(true);
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { fetchLabs(); }, [fetchLabs]);

  const retryLabs = () => {
    setLoading(true);
    setLoadError(false);
    fetchLabs();
  };

  const sortedLabs = useMemo(() => [...labs].sort(byLabNumber), [labs]);
  const topics = useMemo(() => [...new Set(sortedLabs.map(lab => lab.topic).filter(Boolean))], [sortedLabs]);
  const firstLab = sortedLabs[0] || null;
  const resumeLab = sortedLabs.find(lab => lab.slug === resumeSlug) || null;

  const visibleLabs = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return sortedLabs.filter(lab => {
      if (difficulty !== ALL && String(lab.difficulty || 'Beginner').toLowerCase() !== difficulty.toLowerCase()) {
        return false;
      }
      if (topic !== ALL && lab.topic !== topic) return false;
      if (!needle) return true;
      return [lab.title, lab.description, lab.topic]
        .some(value => String(value || '').toLowerCase().includes(needle));
    });
  }, [sortedLabs, query, difficulty, topic]);

  const clearFilters = () => { setQuery(''); setDifficulty(ALL); setTopic(ALL); };
  const resume = resumeLab ? splitTitle(resumeLab.title) : null;

  return (
    <div className={styles.page}>
      <div className={styles.backdrop} aria-hidden="true"><div className={styles.backdropGrid} /></div>

      <header className={styles.nav}>
        <div className={styles.navInner}>
          <Brand />
          <nav className={styles.navLinks} aria-label="Main">
            <a className={styles.navLink} href="#labs">Labs</a>
            <a className={styles.navLink} href="#features">Features</a>
            <a className={styles.navLink} href="#how">How it works</a>
          </nav>
          <a className={`${styles.btnPrimary} ${styles.btnSmall}`} href="#labs">Start learning</a>
        </div>
      </header>

      <section className={styles.hero}>
        <div className={styles.heroCopy}>
          <span className={styles.eyebrow}>
            <span className={styles.eyebrowTag}>CCNA</span>
            Native Cisco IOS simulator, right in your browser
          </span>
          <h1 className={styles.heroTitle}>
            Build real networks.<br />
            <span className={styles.gradientText}>Get graded as you go.</span>
          </h1>
          <p className={styles.heroLead}>
            Configure routers, switches and PCs with a faithful IOS command line. Every lab is a
            live network you build, test and grade task by task, with feedback on exactly what to fix.
          </p>
          <div className={styles.heroActions}>
            {resumeLab ? (
              <a className={styles.btnPrimary} href="#labs">Browse the labs <ArrowRight size={17} /></a>
            ) : (
              <Link className={styles.btnPrimary} href={firstLab ? `/labs/${firstLab.slug}` : '#labs'}>
                <Play size={16} /> Start with {firstLab ? `Lab ${splitTitle(firstLab.title).number || '01'}` : 'the first lab'}
              </Link>
            )}
            <a className={styles.btnSecondary} href={resumeLab ? '#how' : '#labs'}>
              {resumeLab ? 'How it works' : 'Browse the labs'}
            </a>
          </div>
          <div className={styles.heroStats}>
            <div className={styles.stat}><strong>{labs.length || '–'}</strong><span>guided labs</span></div>
            <div className={styles.stat}><strong>300+</strong><span>IOS commands</span></div>
            <div className={styles.stat}><strong>Task by task</strong><span>instant grading</span></div>
            <div className={styles.stat}><strong>Zero</strong><span>installs or images</span></div>
          </div>
        </div>
        <HeroVisual />
      </section>

      {resumeLab && (
        <div className={styles.resume}>
          <div className={styles.resumeCard}>
            <div className={styles.resumeThumb} aria-hidden="true">
              <TopologyRenderer slug={resumeLab.slug} />
            </div>
            <div className={styles.resumeText}>
              <span className={styles.kicker}>Continue where you left off</span>
              <h3>{resume.number ? `Lab ${resume.number} · ${resume.name}` : resume.name}</h3>
              <div className={styles.resumeMeta}>
                <Clock size={14} /> {resumeLab.estimated_time_minutes} min · {resumeLab.topic}
              </div>
            </div>
            <Link className={styles.btnPrimary} href={`/labs/${resumeLab.slug}`}>
              <Play size={16} /> Resume lab
            </Link>
          </div>
        </div>
      )}

      <section id="features" className={styles.section}>
        <div className={styles.sectionHead}>
          <span className={styles.kicker}>Why InstantNodes</span>
          <h2 className={styles.sectionTitle}>Practice that feels like the real thing</h2>
          <p className={styles.sectionLead}>
            A native network simulator built for hands-on learning: the command line, the protocols
            and the grading all work from the same live network state.
          </p>
        </div>
        <div className={styles.features}>
          {FEATURES.map(({ icon: Icon, title, text, chips }) => (
            <article key={title} className={styles.feature}>
              <span className={styles.featureIcon}><Icon size={20} /></span>
              <h3>{title}</h3>
              <p>{text}</p>
              <div className={styles.chips}>
                {chips.map(chip => <span key={chip} className={styles.chip}>{chip}</span>)}
              </div>
            </article>
          ))}
        </div>
      </section>

      <section id="labs" className={styles.section}>
        <div className={styles.catalogHead}>
          <div>
            <span className={styles.kicker}>Lab catalogue</span>
            <h2 className={styles.sectionTitle}>Pick a lab and start configuring</h2>
            <p className={styles.sectionLead}>Each lab is a live topology with tasks, a command reference and grading.</p>
          </div>
          <label className={styles.search}>
            <Search size={17} />
            <input
              type="search"
              className={styles.searchInput}
              placeholder="Search labs, topics, protocols…"
              aria-label="Search labs"
              value={query}
              onChange={event => setQuery(event.target.value)}
            />
          </label>
        </div>

        <div className={styles.filters}>
          <div className={styles.segmented} role="group" aria-label="Difficulty">
            {[ALL, ...DIFFICULTIES].map(level => (
              <button
                key={level}
                type="button"
                className={`${styles.segment} ${difficulty === level ? styles.segmentActive : ''}`}
                aria-pressed={difficulty === level}
                onClick={() => setDifficulty(level)}
              >
                {level === ALL ? 'All levels' : level}
              </button>
            ))}
          </div>
          {[ALL, ...topics].map(name => (
            <button
              key={name}
              type="button"
              className={`${styles.topicChip} ${topic === name ? styles.topicChipActive : ''}`}
              style={{ '--accent': name === ALL ? '#94a3b8' : topicColor(name) }}
              aria-pressed={topic === name}
              onClick={() => setTopic(name)}
            >
              {name === ALL ? 'All topics' : name}
            </button>
          ))}
          {!loading && !loadError && visibleLabs.length !== sortedLabs.length && (
            <span className={styles.resultCount}>
              {`${visibleLabs.length} of ${sortedLabs.length} labs`}
            </span>
          )}
        </div>

        <div className={styles.grid}>
          {loading && [0, 1, 2, 3].map(key => <div key={key} className={styles.skeleton} aria-hidden="true" />)}

          {!loading && loadError && (
            <div className={styles.notice} role="alert">
              <Network size={36} />
              <h3>The labs could not be loaded</h3>
              <p>The lab service did not respond. Check your connection and try again.</p>
              <button type="button" className={styles.btnSecondary} onClick={retryLabs}>Try again</button>
            </div>
          )}

          {!loading && !loadError && visibleLabs.map((lab, index) => (
            <LabCard key={lab.slug} lab={lab} index={index} completed={completed.has(lab.slug)} />
          ))}

          {!loading && !loadError && visibleLabs.length === 0 && (
            <div className={styles.notice}>
              <Search size={36} />
              <h3>No labs match</h3>
              <p>Try a different search term or clear the filters.</p>
              <button type="button" className={styles.btnSecondary} onClick={clearFilters}>Clear filters</button>
            </div>
          )}
        </div>
      </section>

      <section id="how" className={styles.section}>
        <div className={styles.sectionHead}>
          <span className={styles.kicker}>How it works</span>
          <h2 className={styles.sectionTitle}>From blank devices to a working network</h2>
        </div>
        <ol className={styles.steps}>
          {STEPS.map(({ icon: Icon, title, text }, index) => (
            <li key={title} className={styles.step}>
              <span className={styles.stepNumber}>{String(index + 1).padStart(2, '0')}</span>
              <span className={styles.featureIcon}><Icon size={20} /></span>
              <h3>{title}</h3>
              <p>{text}</p>
            </li>
          ))}
        </ol>
      </section>

      <section className={styles.section}>
        <div className={styles.cta}>
          <div>
            <h2>Ready to build your first network?</h2>
            <p>Start with the first lab and work through the catalogue at your own pace.</p>
          </div>
          <Link className={styles.btnPrimary} href={firstLab ? `/labs/${firstLab.slug}` : '#labs'}>
            Start learning <ArrowRight size={17} />
          </Link>
        </div>
      </section>

      <footer className={styles.footer}>
        <div className={styles.footerInner}>
          <Brand />
          <span>Native network simulation for Cisco CCNA practice.</span>
          <nav className={styles.footerLinks} aria-label="Footer">
            <a href="#labs">Labs</a>
            <a href="#features">Features</a>
            <a href="#how">How it works</a>
          </nav>
        </div>
      </footer>
    </div>
  );
}
