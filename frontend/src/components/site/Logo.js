import Link from 'next/link';
import styles from './site.module.css';

// The InstantNodes mark: an N drawn as a network path. Four nodes, three links, and the
// last node lit green, as a link LED does when the line comes up. Also used as app/icon.svg.
export function LogoMark({ size = 28, className = '' }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 32 32" aria-hidden="true" focusable="false">
      <rect width="32" height="32" rx="8" fill="#17365D" />
      <rect x="0.5" y="0.5" width="31" height="31" rx="7.5" fill="none" stroke="rgba(108,180,255,0.35)" />
      <path d="M9 23V9l14 14V9" fill="none" stroke="#6CB4FF" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx="9" cy="23" r="3" fill="#E6F1FF" />
      <circle cx="9" cy="9" r="3" fill="#E6F1FF" />
      <circle cx="23" cy="23" r="3" fill="#E6F1FF" />
      <circle cx="23" cy="9" r="3" fill="#34D27B" />
    </svg>
  );
}

export default function Logo({ href = '/', size = 28, className = '' }) {
  return (
    <Link href={href} className={`${styles.logo} ${className}`} aria-label="InstantNodes home">
      <LogoMark size={size} />
      <span className={styles.wordmark}>InstantNodes</span>
    </Link>
  );
}
