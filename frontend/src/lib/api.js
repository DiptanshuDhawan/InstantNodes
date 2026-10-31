const CONFIGURED_API_URL = process.env.NEXT_PUBLIC_API_URL?.trim();
const REQUEST_TIMEOUT_MS = 20000;

export class ApiError extends Error {
  constructor(message, { status = null, url = null, payload = null, cause = null } = {}) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.url = url;
    this.payload = payload;
    if (cause) this.cause = cause;
  }
}

function trimTrailingSlashes(value) {
  return value.replace(/\/+$/, '');
}

function getFallbackApiUrl() {
  if (typeof window === 'undefined') return 'http://localhost:8000';
  const protocol = window.location.protocol === 'https:' ? 'https:' : 'http:';
  return `${protocol}//${window.location.hostname}:8000`;
}

function getApiBaseUrl() {
  const value = CONFIGURED_API_URL || getFallbackApiUrl();

  try {
    const base = typeof window !== 'undefined'
      ? new URL(value, window.location.origin)
      : new URL(value);

    if (base.protocol !== 'http:' && base.protocol !== 'https:') {
      throw new Error(`Unsupported protocol "${base.protocol}"`);
    }

    return trimTrailingSlashes(base.toString());
  } catch (error) {
    throw new ApiError(`Invalid NEXT_PUBLIC_API_URL: ${error.message}`, { cause: error });
  }
}

function buildUrl(path) {
  return `${getApiBaseUrl()}/${path.replace(/^\/+/, '')}`;
}

function encodePathSegment(value) {
  return encodeURIComponent(String(value));
}

function getErrorDetail(payload) {
  if (typeof payload === 'string' && payload.trim()) return payload.trim();
  if (!payload || typeof payload !== 'object') return null;

  const detail = payload.detail ?? payload.message ?? payload.error;
  if (typeof detail === 'string' && detail.trim()) return detail.trim();
  if (Array.isArray(detail)) {
    const messages = detail
      .map(item => typeof item === 'string' ? item : item?.msg)
      .filter(Boolean);
    if (messages.length) return messages.join('; ');
  }
  return null;
}

// A message for people: the API's own explanation, or what to do when it did not answer.
export function apiErrorMessage(error, fallback = 'Something went wrong. Try again.') {
  if (error instanceof ApiError) {
    if (error.status == null) {
      return 'The lab server did not respond. Check that it is running, then try again.';
    }
    return getErrorDetail(error.payload) || fallback;
  }
  return fallback;
}

async function readPayload(response) {
  if (typeof response.text === 'function') {
    const text = await response.text();
    if (!text) return null;
    try {
      return JSON.parse(text);
    } catch {
      return text;
    }
  }

  if (typeof response.json === 'function') {
    return response.json().catch(() => null);
  }

  return null;
}

async function requestJson(path, { fallbackMessage, json, ...options } = {}) {
  const url = buildUrl(path);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  let response;

  // The sign-in cookie lives on the API host, so every call includes credentials.
  const init = { credentials: 'include', ...options, signal: controller.signal };
  if (json !== undefined) {
    init.headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    init.body = JSON.stringify(json);
  }

  try {
    response = await fetch(url, init);
  } catch (error) {
    const message = error?.name === 'AbortError'
      ? `${fallbackMessage || 'Request failed'}: request timed out`
      : `${fallbackMessage || 'Request failed'}: ${error?.message || 'network error'}`;
    throw new ApiError(message, { url, cause: error });
  } finally {
    clearTimeout(timeoutId);
  }

  const payload = await readPayload(response);
  if (!response.ok) {
    const detail = getErrorDetail(payload);
    const statusLabel = response.status ? ` (HTTP ${response.status})` : '';
    throw new ApiError(
      `${detail || fallbackMessage || 'Request failed'}${statusLabel}`,
      { status: response.status, url, payload }
    );
  }

  if (payload === null) return {};
  if (typeof payload === 'string') {
    throw new ApiError('The server returned an invalid JSON response', {
      status: response.status,
      url,
      payload,
    });
  }
  return payload;
}

export const api = {
  // Accounts. The API sets an HttpOnly session cookie; these return { user }.
  async getMe() {
    return requestJson('/api/auth/me', { fallbackMessage: 'Failed to load your account' });
  },

  async register({ name, email, password }) {
    return requestJson('/api/auth/register', {
      method: 'POST',
      json: { name, email, password },
      fallbackMessage: 'Failed to create the account',
    });
  },

  async login({ email, password }) {
    return requestJson('/api/auth/login', {
      method: 'POST',
      json: { email, password },
      fallbackMessage: 'Failed to sign in',
    });
  },

  async logout({ everywhere = false } = {}) {
    return requestJson(`/api/auth/logout${everywhere ? '?everywhere=true' : ''}`, {
      method: 'POST',
      fallbackMessage: 'Failed to sign out',
    });
  },

  async changePassword({ currentPassword, newPassword }) {
    return requestJson('/api/auth/password', {
      method: 'POST',
      json: { current_password: currentPassword, new_password: newPassword },
      fallbackMessage: 'Failed to change the password',
    });
  },

  // { labs: { [slug]: { attempts, best_percentage, completed, ... } }, active_session }
  async getProgress() {
    return requestJson('/api/progress', { fallbackMessage: 'Failed to load your progress' });
  },

  async getLabs() {
    return requestJson('/api/labs/', { fallbackMessage: 'Failed to fetch labs' });
  },

  async getLab(slug) {
    return requestJson(`/api/labs/${encodePathSegment(slug)}`, {
      fallbackMessage: 'Failed to fetch lab',
    });
  },

  async startSession(labSlug) {
    return requestJson(`/api/session/start/${encodePathSegment(labSlug)}`, {
      method: 'POST',
      fallbackMessage: 'Failed to start session',
    });
  },

  async stopSession(sessionId) {
    return requestJson(`/api/session/stop/${encodePathSegment(sessionId)}`, {
      method: 'POST',
      fallbackMessage: 'Failed to stop session',
    });
  },

  async gradeSession(sessionId) {
    return requestJson(`/api/grade/${encodePathSegment(sessionId)}`, {
      method: 'POST',
      fallbackMessage: 'Failed to grade session',
    });
  },

  async getSessionStatus(sessionId) {
    try {
      return await requestJson(`/api/session/status/${encodePathSegment(sessionId)}`, {
        fallbackMessage: 'Failed to fetch session status',
      });
    } catch (error) {
      const detail = error instanceof ApiError ? getErrorDetail(error.payload) : null;
      if (error instanceof ApiError && error.status === 404 && detail === 'Session not found') {
        return { status: 'stopped', ready: false, nodes: [], links: [] };
      }
      throw error;
    }
  },

  async resetSession(sessionId) {
    return requestJson(`/api/session/reset/${encodePathSegment(sessionId)}`, {
      method: 'POST',
      fallbackMessage: 'Failed to reset session',
    });
  },

  async getIncrementalGrade(sessionId, alreadyPassedIds = []) {
    const queryParams = new URLSearchParams();
    alreadyPassedIds.forEach(id => queryParams.append('already_passed', id));
    const query = queryParams.toString();

    return requestJson(
      `/api/grade/incremental/${encodePathSegment(sessionId)}${query ? `?${query}` : ''}`,
      { fallbackMessage: 'Failed to fetch incremental grade' }
    );
  },

  getTerminalWsUrl(sessionId, nodeName) {
    const apiUrl = new URL(getApiBaseUrl());
    apiUrl.protocol = apiUrl.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsBase = trimTrailingSlashes(apiUrl.toString());
    return `${wsBase}/ws/terminal/${encodePathSegment(sessionId)}/${encodePathSegment(nodeName)}`;
  },
};
