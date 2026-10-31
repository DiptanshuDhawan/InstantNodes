import { IBM_Plex_Mono, IBM_Plex_Sans } from 'next/font/google';

// IBM Plex Sans with its width axis: condensed widths are used for lab numbers and titles.
export const plexSans = IBM_Plex_Sans({
  subsets: ['latin'],
  axes: ['wdth'],
  variable: '--font-sans',
  display: 'swap',
});

// Plex Mono is only used for CLI text (commands), at weight 500.
export const plexMono = IBM_Plex_Mono({
  subsets: ['latin'],
  weight: '500',
  variable: '--font-mono',
  display: 'swap',
});
