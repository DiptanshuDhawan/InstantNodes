import './globals.css';
import { AuthProvider } from '@/components/auth/AuthProvider';
import { plexMono, plexSans } from './fonts';

export const metadata = {
  title: 'InstantNodes',
  description: 'Cisco IOS labs in your browser: configure simulated routers, switches and PCs and get graded task by task.',
};

// The font variables are set on <html> so the logo and the InstantNodes pages share them; the
// lab workspace keeps its own body font (globals.css).
export default function RootLayout({ children }) {
  return (
    <html lang="en" className={`${plexSans.variable} ${plexMono.variable}`}>
      <body>
        <main style={{ margin: 0, padding: 0 }}>
          <AuthProvider>{children}</AuthProvider>
        </main>
      </body>
    </html>
  );
}
