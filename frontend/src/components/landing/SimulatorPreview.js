import RouterIcon from '@/components/icons/RouterIcon';
import styles from './landing.module.css';

// One scripted moment from Lab 02, played once with CSS animation delays: R1 is configured,
// the link comes up and OSPF reaches FULL; then Grade is pressed, the lab's four tasks pass
// and the score shows 100%. With reduced motion every element shows its final state.
// Decorative: the hero text says the same.
const LINES = [
  { at: 0.3, parts: [['p', 'R1#'], ['c', 'configure terminal']] },
  { at: 0.7, parts: [['p', 'R1(config)#'], ['c', 'interface ethernet0/0']] },
  { at: 1.1, parts: [['p', 'R1(config-if)#'], ['c', 'ip address 192.168.1.1 255.255.255.0']] },
  { at: 1.5, parts: [['p', 'R1(config-if)#'], ['c', 'no shutdown']] },
  { at: 2.0, parts: [['l', '%LINK-3-UPDOWN: Interface Ethernet0/0, changed state to up']] },
  { at: 2.6, parts: [['p', 'R1(config-if)#'], ['c', 'router ospf 1']] },
  { at: 3.0, parts: [['p', 'R1(config-router)#'], ['c', 'network 192.168.1.0 0.0.0.255 area 0']] },
  { at: 4.3, parts: [['l', '%OSPF-5-ADJCHG: Process 1, Nbr 192.168.1.2 on Ethernet0/0 from LOADING to '], ['ok', 'FULL'], ['l', ', Loading Done']] },
  { at: 4.9, parts: [['p', 'R1(config-router)#'], ['c', 'end']] },
  { at: 5.2, parts: [['p', 'R1#'], ['cursor', '']] },
];

// The real task names of Lab 02 (labs/ospf-basic/lab.yaml); they pass when Grade is pressed.
const TASKS = [
  { at: 5.8, label: 'R1 Interface Provisioning' },
  { at: 5.95, label: 'R2 Interface Provisioning' },
  { at: 6.1, label: 'OSPF Initialization & Advertisement' },
  { at: 6.25, label: 'Adjacency Verification' },
];

const PART_CLASS = { p: styles.cPrompt, c: styles.cCommand, l: styles.cLog, ok: styles.cOk };

function Check() {
  return (
    <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
      <path d="M3.5 8.5 6.5 11.5 12.5 4.5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export default function SimulatorPreview() {
  return (
    <div className={styles.preview} aria-hidden="true">
      <div className={styles.pvBar}>
        <span className={styles.pvTitle}><b>Lab 02</b><span>OSPF Fundamentals</span></span>
        <span className={styles.pvRun}><i />Running</span>
        <span className={styles.pvGrade}><Check />Grade</span>
        <span className={styles.pvScore}>100%</span>
      </div>
      <div className={styles.pvBody}>
        <div className={styles.pvTasks}>
          <p className={styles.pvLabel}>Tasks</p>
          <ol>
            {TASKS.map(task => (
              <li key={task.label} className={styles.pvTask} style={{ '--d': `${task.at}s` }}>
                <span className={styles.pvMark}>
                  <span className={styles.pvPending} />
                  <span className={styles.pvDone}><Check /></span>
                </span>
                {task.label}
              </li>
            ))}
          </ol>
        </div>
        <div className={styles.pvMain}>
          <div className={styles.pvTopo}>
            <svg viewBox="0 0 440 150" width="100%" height="100%" style={{ fontFamily: 'var(--font-sans), sans-serif' }}>
              <line className={styles.pvLink} x1="90" y1="78" x2="350" y2="78" strokeWidth="2.5" />
              <circle className={styles.pvHello} style={{ '--d': '3.35s' }} cx="132" cy="78" r="3.5" />
              <circle className={styles.pvHello} style={{ '--d': '3.75s' }} cx="132" cy="78" r="3.5" />
              <text x="220" y="62" textAnchor="middle" fill="#E2E8F0" fontSize="12" fontWeight="600">Area 0</text>
              <text x="220" y="102" textAnchor="middle" fill="#A1A9B6" fontSize="11">192.168.1.0/24</text>
              <text x="134" y="66" fill="#E2E8F0" fontSize="11" fontWeight="500">e0/0</text>
              <text x="306" y="66" fill="#E2E8F0" fontSize="11" fontWeight="500" textAnchor="end">e0/1</text>
              <RouterIcon x="90" y="80" label="R1" scale={1.05} active />
              <RouterIcon x="350" y="80" label="R2" scale={1.05} />
            </svg>
          </div>
          <div className={styles.pvConsole}>
            <div className={styles.pvTabs}><span className={styles.pvTabOn}>R1</span><span>R2</span></div>
            <pre className={styles.pvLines}>
              {LINES.map(line => (
                <span key={line.at} className={styles.pvLine} style={{ '--d': `${line.at}s` }}>
                  {line.parts.map(([kind, text]) => (
                    kind === 'cursor'
                      ? <span key={kind} className={styles.cCursor} />
                      : <span key={text} className={PART_CLASS[kind]}>{text}</span>
                  ))}
                </span>
              ))}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}
