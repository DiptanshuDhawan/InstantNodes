import LoginForm from '@/components/auth/LoginForm';

export const metadata = { title: 'Sign in | InstantNodes' };

// The page reads ?next= on the server and hands it to the form (validated there). Without
// it, signing in leads to the lab library.
export default async function LoginPage({ searchParams }) {
  const params = await searchParams;
  return <LoginForm next={typeof params?.next === 'string' ? params.next : '/labs'} />;
}
