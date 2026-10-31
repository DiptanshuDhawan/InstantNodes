import SignupForm from '@/components/auth/SignupForm';

export const metadata = { title: 'Create an account | InstantNodes' };

export default async function SignupPage({ searchParams }) {
  const params = await searchParams;
  return <SignupForm next={typeof params?.next === 'string' ? params.next : '/labs'} />;
}
