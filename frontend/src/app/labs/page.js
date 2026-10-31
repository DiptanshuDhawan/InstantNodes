import LabLibrary from '@/components/library/LabLibrary';

export const metadata = { title: 'Labs | InstantNodes' };

// /labs?lab=<slug> opens the library with that lab selected (links from the home page).
export default async function LabsPage({ searchParams }) {
  const params = await searchParams;
  const lab = typeof params?.lab === 'string' && /^[a-z0-9-]{1,80}$/.test(params.lab) ? params.lab : null;
  return <LabLibrary initialSlug={lab} />;
}
