// The InstantNodes home page: what it is, how a lab runs, what is simulated, the labs and
// accounts. The lab library is at /labs and each lab at /labs/<slug>.
// Design rules: .kiro/skills/instantnodes-ui/SKILL.md

import Link from 'next/link';
import AccountBand from '@/components/landing/AccountBand';
import HeroActions from '@/components/landing/HeroActions';
import LabTeaser from '@/components/landing/LabTeaser';
import SimulatorPreview from '@/components/landing/SimulatorPreview';
import Logo from '@/components/site/Logo';
import SiteHeader from '@/components/site/SiteHeader';
import styles from '@/components/landing/landing.module.css';

const SPECS = [
  ['Devices', <>Routers, layer 2 switches and PCs.</>],
  ['Command line', <>More than 300 IOS commands, with <code>?</code> help, Tab completion, abbreviations and <code>do</code> from configuration mode.</>],
  ['Switching', <>VLANs, 802.1Q trunks, VTP, PVST+ spanning tree with PortFast and BPDU guard, port security, and EtherChannel with LACP or PAgP.</>],
  ['Routing', <>Static routes, single-area OSPF, and router-on-a-stick with 802.1Q subinterfaces.</>],
  ['Services', <>DHCP server and relay, NTP with authentication, SSH and Telnet, CDP and LLDP, and syslog messages.</>],
  ['Verification', <><code>show</code> output built from the live network state, <code>ping</code> and <code>traceroute</code>.</>],
  ['Grading', <>Each task is checked against the running configuration, the device state and connectivity, and failed tasks say what is missing.</>],
  ['Runs in', <>Any modern browser. Nothing to install and no device images.</>],
];

function RouterGlyph() {
  return (
    <svg className={styles.glyph} width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.2" aria-hidden="true">
      <path d="M2 6.2v3.6c0 1.4 2.7 2.6 6 2.6s6-1.2 6-2.6V6.2" />
      <ellipse cx="8" cy="6.2" rx="6" ry="2.5" />
      <path d="M6.2 6.2h3.6M8 5.1v2.2" strokeWidth="1" strokeLinecap="round" />
    </svg>
  );
}

function SwitchGlyph() {
  return (
    <svg className={styles.glyph} width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="1.5" y="4.5" width="13" height="7" rx="1.2" />
      <path d="M4.5 7h6.5M9.6 5.9 11 7 9.6 8.1M11.5 9H5M6.4 7.9 5 9l1.4 1.1" strokeWidth="1" />
    </svg>
  );
}

export default function HomePage() {
  return (
    <div className={styles.page}>
      <SiteHeader contained sticky />

      <div className={styles.content}>
        <section className={styles.hero} aria-labelledby="hero-title">
          <div>
            <h1 id="hero-title" className={styles.heroTitle}>A CCNA lab bench in your browser</h1>
            <p className={styles.heroLead}>
              Start routers, switches and PCs in seconds, configure them from an IOS command line,
              and grade your work task by task.
            </p>
            <HeroActions />
            <p className={styles.heroNote}>Nothing to install. Works in any modern browser.</p>
          </div>
          <SimulatorPreview />
        </section>

        <section id="how" className={styles.section} aria-labelledby="how-title">
          <div className={styles.sectionHead}>
            <div>
              <h2 id="how-title" className={styles.sectionTitle}>How a lab runs</h2>
              <p className={styles.sectionLead}>
                Every lab is a small network that you build yourself, from the first interface to a
                working service.
              </p>
            </div>
          </div>
          <ol className={styles.stages}>
            <li className={styles.stage}>
              <span className={styles.stageNo}>1</span>
              <h3 className={styles.stageTitle}>Start the lab</h3>
              <p className={styles.stageText}>Press Start and the devices boot on the lab server, each with its own console.</p>
              <div className={styles.artifact}>
                <ul className={styles.devices}>
                  <li><RouterGlyph />R1<span><i className={styles.led} aria-hidden="true" /> Ready</span></li>
                  <li><SwitchGlyph />SW1<span><i className={styles.led} aria-hidden="true" /> Ready</span></li>
                  <li><RouterGlyph />R2<span><i className={styles.led} aria-hidden="true" /> Ready</span></li>
                </ul>
              </div>
            </li>
            <li className={styles.stage}>
              <span className={styles.stageNo}>2</span>
              <h3 className={styles.stageTitle}>Configure from the console</h3>
              <p className={styles.stageText}>Type IOS commands as on real equipment. <code>?</code> lists what can come next.</p>
              <div className={styles.artifact}>
                <pre className={styles.snippet}>
                  <span className={styles.cPrompt}>R1(config)#</span><span className={styles.cCommand}>router ospf 1</span>{'\n'}
                  <span className={styles.cPrompt}>R1(config-router)#</span><span className={styles.cCommand}>network ?</span>{'\n'}
                  <span className={styles.snippetHelp}>{'  A.B.C.D  Network number'}</span>{'\n'}
                  <span className={styles.cPrompt}>R1(config-router)#</span><span className={styles.cCommand}>network </span>
                </pre>
              </div>
            </li>
            <li className={styles.stage}>
              <span className={styles.stageNo}>3</span>
              <h3 className={styles.stageTitle}>Grade your work</h3>
              <p className={styles.stageText}>Grade at any time. Each task passes, or says what is still missing.</p>
              <div className={styles.artifact}>
                <ul className={styles.results}>
                  <li><i className={styles.led} aria-hidden="true" /><span><span className={styles.srOnly}>Complete: </span>R1 Interface Provisioning</span></li>
                  <li><i className={styles.led} aria-hidden="true" /><span><span className={styles.srOnly}>Complete: </span>R2 Interface Provisioning</span></li>
                  <li>
                    <i className={`${styles.led} ${styles.ledFail}`} aria-hidden="true" />
                    <span>
                      <span className={styles.srOnly}>Not complete: </span>
                      OSPF Initialization &amp; Advertisement
                      <span className={styles.finding}>R2: router ospf 1 is not configured.</span>
                    </span>
                  </li>
                </ul>
              </div>
            </li>
          </ol>
        </section>

        <section id="simulated" className={styles.section} aria-labelledby="simulated-title">
          <div className={styles.sectionHead}>
            <div>
              <h2 id="simulated-title" className={styles.sectionTitle}>What’s simulated</h2>
              <p className={styles.sectionLead}>
                The parts of IOS the CCNA labs need, modelled so that a mistake fails for the same
                reason it would on real equipment. Commands outside that set are refused with a message.
              </p>
            </div>
          </div>
          <table className={styles.spec}>
            <tbody>
              {SPECS.map(([label, text]) => (
                <tr key={label}>
                  <th scope="row">{label}</th>
                  <td>{text}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>

        {/* After the linked sections (#how, #simulated): the list loads from the API and grows,
            which would move a section below it after a jump from the top bar. */}
        <section id="labs" className={styles.section} aria-labelledby="labs-title">
          <div className={styles.sectionHead}>
            <div>
              <h2 id="labs-title" className={styles.sectionTitle}>Labs you can open now</h2>
              <p className={styles.sectionLead}>
                Each lab comes with a topology, step-by-step tasks and a command reference.
              </p>
            </div>
            <Link href="/labs" className={styles.buttonQuiet}>Browse the labs</Link>
          </div>
          <LabTeaser />
        </section>

        <AccountBand />
      </div>

      <footer className={styles.footer}>
        <div className={styles.footerInner}>
          <div>
            <Logo size={24} />
            <p className={styles.footerText}>Practice Cisco IOS configuration for the CCNA, in your browser.</p>
          </div>
          <ul className={styles.footerLinks}>
            <li><Link href="/labs">Labs</Link></li>
            <li><Link href="/#how">How it works</Link></li>
            <li><Link href="/#simulated">What’s simulated</Link></li>
            <li><Link href="/account">Your account</Link></li>
          </ul>
          <p className={styles.legal}>
            Cisco, Cisco IOS and CCNA are trademarks of Cisco Systems, Inc. InstantNodes is not
            affiliated with Cisco.
          </p>
        </div>
      </footer>
    </div>
  );
}
