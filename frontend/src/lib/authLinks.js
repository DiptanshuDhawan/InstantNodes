// Links to the sign-in pages that remember where to return. Plain functions (no client
// directive), so both Server and Client Components can use them.

// Only same-site paths are accepted as a place to return to after signing in.
export function safeNext(value, fallback = '/') {
  const text = typeof value === 'string' ? value : '';
  return text.startsWith('/') && !text.startsWith('//') && !text.startsWith('/\\') ? text : fallback;
}

function withNext(path, next) {
  const target = safeNext(next, '');
  return target && target !== '/' ? `${path}?next=${encodeURIComponent(target)}` : path;
}

export function loginHref(next) {
  return withNext('/login', next);
}

export function signupHref(next) {
  return withNext('/signup', next);
}
