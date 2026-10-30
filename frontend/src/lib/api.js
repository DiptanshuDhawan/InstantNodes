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

async function requestJson(path, { fallbackMessage, ...options } = {}) {
  const url = buildUrl(path);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  let response;

  try {
    response = await fetch(url, { ...options, signal: controller.signal });
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
