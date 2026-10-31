import { useState, useEffect, useRef, useCallback } from 'react';
import { api } from '@/lib/api';

const SESSION_STORAGE_KEY = 'netlabx_session';
const SESSION_STORAGE_VERSION = 1;
const SESSION_RUNTIME = 'native';
const BOOT_TIMEOUT_MS = 45000;
const BOOT_POLL_MS = 750;
const STATUS_POLL_MS = 5000;
const MAX_BOOT_STATUS_ERRORS = 4;
const SOCKET_CONNECT_TIMEOUT_MS = 10000;
const MAX_SOCKET_RETRIES = 6;
const SOCKET_SLOW_RETRY_MS = 15000;
const MAX_BUFFER_CHUNKS = 500;

const READY_STATES = new Set(['ready', 'running', 'started', 'online', 'up', 'active', 'connected', 'booted']);
const STOPPED_STATES = new Set(['stopped', 'stop', 'offline', 'closed', 'terminated', 'not_found']);
const FAILED_STATES = new Set(['failed', 'error', 'faulted']);

function normalizeState(value) {
  if (typeof value === 'boolean') return value ? 'ready' : 'stopped';
  if (value && typeof value === 'object') {
    return normalizeState(value.status ?? value.state ?? value.phase ?? value.ready);
  }
  return value == null ? '' : String(value).trim().toLowerCase();
}

function extractNodeStatuses(payload) {
  const source = payload?.node_statuses ?? payload?.nodeStatuses ?? payload?.nodes;
  const statuses = {};

  if (Array.isArray(source)) {
    source.forEach((node) => {
      if (typeof node === 'string') return;
      const name = node?.name ?? node?.node_name ?? node?.id;
      if (name != null) statuses[String(name)] = normalizeState(node);
    });
  } else if (source && typeof source === 'object') {
    Object.entries(source).forEach(([name, value]) => {
      statuses[name] = normalizeState(value);
    });
  }

  return { statuses, supplied: source !== undefined };
}

function findNodeStatus(statuses, nodeName) {
  if (statuses[nodeName] !== undefined) return statuses[nodeName];
  const match = Object.entries(statuses)
    .find(([name]) => name.toLowerCase() === String(nodeName).toLowerCase());
  return match?.[1];
}

function extractGeneration(payload) {
  return payload?.generation ?? payload?.runtime_generation ?? payload?.reset_generation ?? null;
}

function extractProgress(payload) {
  const raw = payload?.progress ?? payload?.boot_progress ?? payload?.bootProgress;
  const value = Number(raw);
  if (!Number.isFinite(value)) return null;
  return Math.max(0, Math.min(100, value > 0 && value <= 1 ? value * 100 : value));
}

function normalizeStatusPayload(payload, expectedNodeNames = []) {
  const state = normalizeState(payload?.status ?? payload?.state ?? payload?.phase);
  const { statuses, supplied } = extractNodeStatuses(payload);
  const explicitReady = typeof payload?.ready === 'boolean'
    ? payload.ready
    : typeof payload?.nodes_ready === 'boolean'
      ? payload.nodes_ready
      : null;

  let ready = explicitReady;
  if (ready === null) {
    const values = expectedNodeNames.length
      ? expectedNodeNames.map(name => findNodeStatus(statuses, name))
      : Object.values(statuses);
    ready = values.length > 0 && values.every(value => READY_STATES.has(normalizeState(value)));
    if (values.length === 0) ready = READY_STATES.has(state);
  }

  return {
    state,
    ready: Boolean(ready),
    stopped: STOPPED_STATES.has(state),
    failed: FAILED_STATES.has(state),
    error: typeof payload?.error === 'string' ? payload.error : null,
    generation: extractGeneration(payload),
    progress: extractProgress(payload),
    nodeStatuses: statuses,
    nodeStatusesSupplied: supplied,
    links: Array.isArray(payload?.links) ? payload.links : null,
  };
}

function sameGeneration(left, right) {
  return left != null && right != null && String(left) === String(right);
}

function compareGenerations(left, right) {
  const leftNumber = Number(left);
  const rightNumber = Number(right);
  if (Number.isFinite(leftNumber) && Number.isFinite(rightNumber)) {
    return Math.sign(leftNumber - rightNumber);
  }
  return sameGeneration(left, right) ? 0 : null;
}

function isValidSessionId(value) {
  if (typeof value === 'number') return Number.isSafeInteger(value) && value > 0;
  if (typeof value !== 'string') return false;

  const normalized = value.trim();
  if (!/^\d+$/.test(normalized)) return false;
  const numericValue = Number(normalized);
  return Number.isSafeInteger(numericValue) && numericValue > 0;
}

function makeStoredSession(session, slug, generation, startedAt = session?.startedAt) {
  return {
    ...session,
    version: SESSION_STORAGE_VERSION,
    runtime: SESSION_RUNTIME,
    slug,
    generation: generation ?? null,
    ...(startedAt ? { startedAt } : {}),
  };
}

function persistSession(session) {
  try {
    localStorage.setItem(SESSION_STORAGE_KEY, JSON.stringify(session));
  } catch {
    // Storage may be unavailable in privacy mode; the active in-memory session remains usable.
  }
}

function removeStoredSession(expectedSessionId = null) {
  try {
    if (expectedSessionId == null) {
      localStorage.removeItem(SESSION_STORAGE_KEY);
      return;
    }

    const raw = localStorage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw);
    if (String(parsed?.session_id) === String(expectedSessionId)) {
      localStorage.removeItem(SESSION_STORAGE_KEY);
    }
  } catch {
    localStorage.removeItem(SESSION_STORAGE_KEY);
  }
}

function readStoredSession(slug) {
  let raw;
  try {
    raw = localStorage.getItem(SESSION_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    const supportedVersion = parsed?.version == null || parsed.version === SESSION_STORAGE_VERSION;
    const supportedRuntime = parsed?.runtime == null || parsed.runtime === SESSION_RUNTIME;

    if (!parsed || typeof parsed !== 'object' || !supportedVersion || !supportedRuntime || !isValidSessionId(parsed.session_id)) {
      localStorage.removeItem(SESSION_STORAGE_KEY);
      return null;
    }
    if (parsed.slug !== slug) return null;
    return parsed;
  } catch {
    if (raw) localStorage.removeItem(SESSION_STORAGE_KEY);
    return null;
  }
}

function readStoredTasks(sessionId) {
  const key = `netlabx_tasks_${sessionId}`;
  try {
    const parsed = JSON.parse(localStorage.getItem(key) || '[]');
    if (!Array.isArray(parsed)) throw new Error('Invalid task data');
    return parsed;
  } catch {
    localStorage.removeItem(key);
    return [];
  }
}

// The account's running lab when this browser has no record of it (another device, or
// storage was cleared), in the stored-session shape; null if it runs another lab or none.
function findServerSession(slug) {
  return api.getProgress()
    .then((progress) => {
      const active = progress?.active_session;
      if (!active || active.lab_slug !== slug || !isValidSessionId(active.session_id)) return null;
      const startedAt = Date.parse(active.started_at);
      return {
        session_id: active.session_id,
        version: SESSION_STORAGE_VERSION,
        runtime: SESSION_RUNTIME,
        slug,
        generation: active.generation ?? null,
        ...(Number.isFinite(startedAt) ? { startedAt } : {}),
      };
    })
    .catch(() => null);
}

export function useLabSession(slug) {
  const [lab, setLab] = useState(null);
  const [allLabs, setAllLabs] = useState([]);
  const [session, setSession] = useState(null);
  const [generation, setGeneration] = useState(null);
  const [nodeStatuses, setNodeStatuses] = useState({});
  const [terminalStatuses, setTerminalStatuses] = useState({});
  const [runtimeReady, setRuntimeReady] = useState(false);
  const [bootOperation, setBootOperation] = useState(null);

  const [activeTerminal, setActiveTerminal] = useState('R1');
  const [isGrading, setIsGrading] = useState(false);
  const [gradeReport, setGradeReport] = useState(null);
  const [loading, setLoading] = useState(true);

  const [visibleHints, setVisibleHints] = useState({});
  const [visibleAnswers, setVisibleAnswers] = useState({});
  const [showCompletionModal, setShowCompletionModal] = useState(false);
  const [showFailModal, setShowFailModal] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);

  const [labTimer, setLabTimer] = useState(0);
  const [isBooting, setIsBooting] = useState(false);
  const [bootProgress, setBootProgress] = useState(0);
  const [linkStatus, setLinkStatus] = useState([]);
  const [termFontSize, setTermFontSize] = useState(16);
  const [taskProgress, setTaskProgress] = useState([]);
  const [passedTaskIds, setPassedTaskIds] = useState([]);
  const [showResetModal, setShowResetModal] = useState(false);
  const [statusCycle, setStatusCycle] = useState(0);
  const [socketCycle, setSocketCycle] = useState(0);

  const wsRefs = useRef({});
  const bufRefs = useRef({});
  const mountedRef = useRef(true);
  const sessionRef = useRef(null);
  const generationRef = useRef(null);
  const operationTokenRef = useRef(0);
  const statusPollTokenRef = useRef(0);
  const socketOwnerRef = useRef(0);
  const socketTimersRef = useRef(new Set());
  const statusErrorRef = useRef(null);
  const terminalErrorRef = useRef({});
  const bootRef = useRef({
    active: false,
    deadline: 0,
    expectedGeneration: null,
    operation: null,
  });

  const clearError = useCallback(() => {
    statusErrorRef.current = null;
    setErrorMsg(null);
  }, []);

  const clearStatusError = useCallback(() => {
    const previousStatusError = statusErrorRef.current;
    statusErrorRef.current = null;
    if (previousStatusError) {
      setErrorMsg(current => current === previousStatusError ? null : current);
    }
  }, []);

  const closeAllSockets = useCallback((clearBuffers = true) => {
    socketOwnerRef.current += 1;
    socketTimersRef.current.forEach(timerId => clearTimeout(timerId));
    socketTimersRef.current.clear();

    Object.values(wsRefs.current).forEach((ws) => {
      if (!ws) return;
      ws.onopen = null;
      ws.onmessage = null;
      ws.onerror = null;
      ws.onclose = null;
      try {
        if (ws.readyState === 0 || ws.readyState === 1) ws.close();
      } catch {
        // The reference is still removed below even if the browser rejects close().
      }
    });

    wsRefs.current = {};
    if (clearBuffers) bufRefs.current = {};
    terminalErrorRef.current = {};
    if (mountedRef.current) {
      setTerminalStatuses({});
      setSocketCycle(value => value + 1);
    }
  }, []);

  const commitSession = useCallback((nextSession) => {
    sessionRef.current = nextSession;
    setSession(nextSession);
    if (nextSession) persistSession(nextSession);
  }, []);

  const clearSessionLocally = useCallback((expectedSessionId = sessionRef.current?.session_id) => {
    operationTokenRef.current += 1;
    statusPollTokenRef.current += 1;
    bootRef.current = { active: false, deadline: 0, expectedGeneration: null, operation: null };
    closeAllSockets(true);

    sessionRef.current = null;
    generationRef.current = null;
    setSession(null);
    setGeneration(null);
    setNodeStatuses({});
    setLinkStatus([]);
    setRuntimeReady(false);
    setIsBooting(false);
    setBootOperation(null);
    setBootProgress(0);
    setGradeReport(null);
    setVisibleHints({});
    setVisibleAnswers({});
    setTaskProgress([]);
    setPassedTaskIds([]);
    setLabTimer(0);
    clearError();

    removeStoredSession(expectedSessionId);
    if (expectedSessionId != null) {
      try {
        localStorage.removeItem(`netlabx_tasks_${expectedSessionId}`);
      } catch {
        // Ignore unavailable storage.
      }
    }
  }, [clearError, closeAllSockets]);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      operationTokenRef.current += 1;
      statusPollTokenRef.current += 1;
      closeAllSockets(true);
    };
  }, [closeAllSockets]);

  useEffect(() => {
    let cancelled = false;

    Promise.resolve()
      .then(() => {
        if (cancelled) return null;
        setLoading(true);
        setLab(null);
        setAllLabs([]);
        clearError();
        return Promise.all([
          api.getLab(slug),
          api.getLabs().catch(() => []),
        ]);
      })
      .then((result) => {
        if (cancelled || !result) return;
        const [currentLab, allLabsData] = result;
        setLab(currentLab);
        setAllLabs(allLabsData);
        if (currentLab?.nodes?.length > 0) {
          setActiveTerminal(currentLab.nodes[0].name);
        }
      })
      .catch((error) => {
        if (!cancelled) setErrorMsg(`Unable to load Native Simulation: ${error.message}`);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [slug, clearError]);

  useEffect(() => {
    let cancelled = false;
    let stored = null;
    const operationToken = ++operationTokenRef.current;
    statusPollTokenRef.current += 1;

    Promise.resolve()
      .then(() => {
        if (cancelled || operationTokenRef.current !== operationToken) return null;
        closeAllSockets(true);
        bootRef.current = { active: false, deadline: 0, expectedGeneration: null, operation: null };
        sessionRef.current = null;
        generationRef.current = null;
        setSession(null);
        setGeneration(null);
        setNodeStatuses({});
        setLinkStatus([]);
        setRuntimeReady(false);
        setIsBooting(false);
        setBootOperation(null);
        setBootProgress(0);
        setLabTimer(0);
        setGradeReport(null);
        setTaskProgress([]);
        setPassedTaskIds([]);

        stored = readStoredSession(slug);
        return stored || findServerSession(slug);
      })
      .then((found) => {
        if (cancelled || operationTokenRef.current !== operationToken || !found) return null;
        stored = found;

        setIsBooting(true);
        setBootOperation('restoring');
        setBootProgress(10);
        return api.getSessionStatus(stored.session_id);
      })
      .then((payload) => {
        if (cancelled || operationTokenRef.current !== operationToken || !stored || !payload) return;
        const info = normalizeStatusPayload(payload);
        if (info.stopped) {
          removeStoredSession(stored.session_id);
          try {
            localStorage.removeItem(`netlabx_tasks_${stored.session_id}`);
          } catch {
            // Ignore unavailable storage.
          }
          setIsBooting(false);
          setBootOperation(null);
          setBootProgress(0);
          return;
        }
        if (info.failed || info.error) {
          throw new Error(info.error || `Runtime reported ${info.state || 'a failure'}`);
        }

        const restoredGeneration = info.generation ?? stored.generation ?? null;
        const startedAt = Number(stored.startedAt) > 0 ? Number(stored.startedAt) : null;
        const restoredSession = makeStoredSession(stored, slug, restoredGeneration, startedAt);
        generationRef.current = restoredGeneration;
        setGeneration(restoredGeneration);
        commitSession(restoredSession);
        if (info.nodeStatusesSupplied) setNodeStatuses(info.nodeStatuses);
        if (info.links) setLinkStatus(info.links);

        const tasks = readStoredTasks(stored.session_id);
        setTaskProgress(tasks);
        setPassedTaskIds(tasks.map(task => task.task_id).filter(id => id != null));
        if (startedAt) setLabTimer(Math.max(0, Math.floor((Date.now() - startedAt) / 1000)));

        if (info.ready) {
          const readyAt = startedAt || Date.now();
          const readySession = makeStoredSession(restoredSession, slug, restoredGeneration, readyAt);
          commitSession(readySession);
          bootRef.current = { active: false, deadline: 0, expectedGeneration: null, operation: null };
          setRuntimeReady(true);
          setIsBooting(false);
          setBootOperation(null);
          setBootProgress(100);
        } else {
          bootRef.current = {
            active: true,
            deadline: Date.now() + BOOT_TIMEOUT_MS,
            expectedGeneration: info.generation,
            operation: 'restoring',
          };
          setRuntimeReady(false);
        }
        setStatusCycle(value => value + 1);
      })
      .catch((error) => {
        if (cancelled || operationTokenRef.current !== operationToken) return;
        bootRef.current = { active: false, deadline: 0, expectedGeneration: null, operation: null };
        setIsBooting(false);
        setBootOperation(null);
        setBootProgress(0);
        setRuntimeReady(false);
        setErrorMsg(`Unable to restore the saved Native Simulation session: ${error.message}`);
      });

    return () => {
      cancelled = true;
      if (operationTokenRef.current === operationToken) operationTokenRef.current += 1;
    };
  }, [slug, closeAllSockets, commitSession]);

  const labNodeNames = lab?.nodes?.map(node => node.name) || [];
  const labNodeKey = JSON.stringify(labNodeNames);

  useEffect(() => {
    const sessionId = session?.session_id;
    if (!isValidSessionId(sessionId)) return;

    let cancelled = false;
    let pollTimer = null;
    let consecutiveErrors = 0;
    const pollToken = ++statusPollTokenRef.current;
    const expectedNodeNames = JSON.parse(labNodeKey);

    const schedule = (delay) => {
      if (cancelled || statusPollTokenRef.current !== pollToken) return;
      pollTimer = setTimeout(poll, delay);
    };

    const failBoot = (message) => {
      bootRef.current = { active: false, deadline: 0, expectedGeneration: null, operation: null };
      setRuntimeReady(false);
      setIsBooting(false);
      setBootOperation(null);
      setBootProgress(progress => Math.min(progress, 99));
      statusErrorRef.current = message;
      setErrorMsg(message);
    };

    const updateGeneration = (observedGeneration) => {
      if (observedGeneration == null || sameGeneration(observedGeneration, generationRef.current)) return;
      generationRef.current = observedGeneration;
      setGeneration(observedGeneration);
      const current = sessionRef.current;
      if (current && String(current.session_id) === String(sessionId)) {
        commitSession(makeStoredSession(current, slug, observedGeneration));
      }
    };

    const markReady = (observedGeneration) => {
      if (observedGeneration != null) updateGeneration(observedGeneration);
      bootRef.current = { active: false, deadline: 0, expectedGeneration: null, operation: null };
      setRuntimeReady(true);
      setIsBooting(false);
      setBootOperation(null);
      setBootProgress(100);

      const current = sessionRef.current;
      if (current && String(current.session_id) === String(sessionId) && !current.startedAt) {
        const readySession = makeStoredSession(current, slug, observedGeneration ?? generationRef.current, Date.now());
        commitSession(readySession);
      }
    };

    async function poll() {
      if (cancelled || statusPollTokenRef.current !== pollToken) return;
      try {
        const payload = await api.getSessionStatus(sessionId);
        if (cancelled || statusPollTokenRef.current !== pollToken) return;
        const info = normalizeStatusPayload(payload, expectedNodeNames);

        if (info.stopped) {
          clearSessionLocally(sessionId);
          return;
        }
        if (info.nodeStatusesSupplied) setNodeStatuses(info.nodeStatuses);
        if (info.links) setLinkStatus(info.links);
        if (info.error) throw new Error(info.error);
        if (info.failed) {
          failBoot(`Native Simulation failed to start${info.state ? ` (${info.state})` : ''}.`);
          schedule(STATUS_POLL_MS);
          return;
        }

        consecutiveErrors = 0;
        clearStatusError();

        let expectedGeneration = bootRef.current.expectedGeneration;
        let generationMatches = expectedGeneration == null;
        if (expectedGeneration != null) {
          generationMatches = sameGeneration(info.generation, expectedGeneration);
          const comparison = info.generation == null ? null : compareGenerations(info.generation, expectedGeneration);
          if (comparison === 1) {
            expectedGeneration = info.generation;
            bootRef.current.expectedGeneration = info.generation;
            generationMatches = true;
          }
        }

        if (expectedGeneration == null || generationMatches) {
          updateGeneration(info.generation);
        }

        if (info.ready && generationMatches) {
          markReady(info.generation);
        } else {
          setRuntimeReady(false);
          if (!bootRef.current.active) {
            bootRef.current = {
              active: true,
              deadline: Date.now() + BOOT_TIMEOUT_MS,
              expectedGeneration: info.generation,
              operation: 'reconnecting',
            };
            setIsBooting(true);
            setBootOperation('reconnecting');
            setBootProgress(info.progress ?? 10);
          } else if (info.progress != null) {
            setBootProgress(Math.floor(info.progress));
          } else {
            const remaining = Math.max(0, bootRef.current.deadline - Date.now());
            const elapsedRatio = 1 - (remaining / BOOT_TIMEOUT_MS);
            setBootProgress(Math.max(10, Math.min(95, Math.floor(10 + elapsedRatio * 85))));
          }

          if (Date.now() >= bootRef.current.deadline) {
            failBoot('Native Simulation did not become ready in time. You can reset or stop the session.');
          }
        }

        schedule(bootRef.current.active ? BOOT_POLL_MS : STATUS_POLL_MS);
      } catch (error) {
        if (cancelled || statusPollTokenRef.current !== pollToken) return;
        consecutiveErrors += 1;
        const message = `Unable to check Native Simulation status: ${error.message}`;
        statusErrorRef.current = message;
        setErrorMsg(message);

        const bootExpired = bootRef.current.active && (
          Date.now() >= bootRef.current.deadline || consecutiveErrors >= MAX_BOOT_STATUS_ERRORS
        );
        if (bootExpired) failBoot(`${message}. Boot monitoring stopped; retry reset or stop the session.`);
        schedule(bootRef.current.active ? BOOT_POLL_MS : STATUS_POLL_MS);
      }
    }

    poll();
    return () => {
      cancelled = true;
      clearTimeout(pollTimer);
      if (statusPollTokenRef.current === pollToken) statusPollTokenRef.current += 1;
    };
  }, [session?.session_id, statusCycle, labNodeKey, slug, clearSessionLocally, clearStatusError, commitSession]);

  useEffect(() => {
    if (!session?.startedAt || isBooting || !runtimeReady) return;

    const updateTimer = () => {
      setLabTimer(Math.max(0, Math.floor((Date.now() - session.startedAt) / 1000)));
    };
    updateTimer();
    const interval = setInterval(updateTimer, 1000);
    return () => clearInterval(interval);
  }, [session?.startedAt, isBooting, runtimeReady]);

  useEffect(() => {
    if (!session?.session_id || !runtimeReady || labNodeNames.length === 0) return;

    closeAllSockets(true);
    const owner = socketOwnerRef.current;
    let disposed = false;

    const updateTerminalStatus = (nodeName, status) => {
      if (disposed || socketOwnerRef.current !== owner || !mountedRef.current) return;
      setTerminalStatuses(current => ({ ...current, [nodeName]: status }));
    };

    const scheduleReconnect = (nodeName, attempt, reason) => {
      if (disposed || socketOwnerRef.current !== owner) return;
      const slowRetry = attempt > MAX_SOCKET_RETRIES;

      if (slowRetry) {
        updateTerminalStatus(nodeName, 'disconnected');
        if (!terminalErrorRef.current[nodeName]) {
          const message = `Terminal for ${nodeName} is disconnected; background retries will continue${reason ? `: ${reason}` : '.'}`;
          terminalErrorRef.current[nodeName] = message;
          setErrorMsg(message);
        }
      } else {
        updateTerminalStatus(nodeName, 'reconnecting');
      }

      const delay = slowRetry
        ? SOCKET_SLOW_RETRY_MS
        : Math.min(5000, 500 * (2 ** Math.max(0, attempt - 1)));
      const nextAttempt = slowRetry ? MAX_SOCKET_RETRIES + 1 : attempt;
      const timerId = setTimeout(() => {
        socketTimersRef.current.delete(timerId);
        connectNode(nodeName, nextAttempt);
      }, delay);
      socketTimersRef.current.add(timerId);
    };

    const connectNode = (nodeName, attempt = 0) => {
      if (disposed || socketOwnerRef.current !== owner) return;
      updateTerminalStatus(nodeName, attempt === 0 ? 'connecting' : 'reconnecting');

      let ws;
      try {
        ws = new WebSocket(api.getTerminalWsUrl(session.session_id, nodeName));
      } catch (error) {
        scheduleReconnect(nodeName, attempt + 1, error.message);
        return;
      }

      ws.binaryType = 'arraybuffer';
      wsRefs.current[nodeName] = ws;
      setSocketCycle(value => value + 1);
      let disconnected = false;
      let opened = false;

      const connectTimeout = setTimeout(() => {
        socketTimersRef.current.delete(connectTimeout);
        disconnect({ code: 1006, reason: 'connection timed out' });
        try { ws.close(); } catch { /* reference cleanup happens in disconnect */ }
      }, SOCKET_CONNECT_TIMEOUT_MS);
      socketTimersRef.current.add(connectTimeout);

      const disconnect = (event = {}) => {
        if (disconnected) return;
        disconnected = true;
        clearTimeout(connectTimeout);
        socketTimersRef.current.delete(connectTimeout);
        if (wsRefs.current[nodeName] === ws) delete wsRefs.current[nodeName];
        if (disposed || socketOwnerRef.current !== owner) return;
        setSocketCycle(value => value + 1);

        const reason = event.reason || (event.code ? `connection closed (${event.code})` : 'connection closed');
        if (event.code === 1008) {
          updateTerminalStatus(nodeName, 'failed');
          const message = `Terminal for ${nodeName} was rejected: ${reason}`;
          terminalErrorRef.current[nodeName] = message;
          setErrorMsg(message);
          return;
        }
        scheduleReconnect(nodeName, opened ? 1 : attempt + 1, reason);
      };

      ws.onopen = () => {
        if (disposed || socketOwnerRef.current !== owner) {
          try { ws.close(); } catch { /* stale socket */ }
          return;
        }
        opened = true;
        clearTimeout(connectTimeout);
        socketTimersRef.current.delete(connectTimeout);
        updateTerminalStatus(nodeName, 'connected');
        const previousError = terminalErrorRef.current[nodeName];
        delete terminalErrorRef.current[nodeName];
        if (previousError) setErrorMsg(current => current === previousError ? null : current);
      };

      ws.onerror = () => {
        disconnect({ code: 1006, reason: 'connection error' });
        try { ws.close(); } catch { /* reference cleanup happens in disconnect */ }
      };
      ws.onclose = disconnect;
      ws.onmessage = (event) => {
        if (disposed || socketOwnerRef.current !== owner) return;
        const chunk = typeof event.data === 'string'
          ? new TextEncoder().encode(event.data)
          : new Uint8Array(event.data);
        bufRefs.current[nodeName] = bufRefs.current[nodeName] || [];
        bufRefs.current[nodeName].push(chunk);
        while (bufRefs.current[nodeName].length > MAX_BUFFER_CHUNKS) {
          bufRefs.current[nodeName].shift();
        }
      };
    };

    labNodeNames.forEach((nodeName) => {
      bufRefs.current[nodeName] = [];
      connectNode(nodeName);
    });

    return () => {
      disposed = true;
      if (socketOwnerRef.current === owner) closeAllSockets(true);
    };
  // labNodeKey intentionally represents the stable list of terminal node names.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session?.session_id, generation, runtimeReady, labNodeKey, closeAllSockets]);

  const handleStart = async () => {
    if (sessionRef.current) return;
    const operationToken = ++operationTokenRef.current;
    statusPollTokenRef.current += 1;
    clearError();
    closeAllSockets(true);
    bootRef.current = {
      active: true,
      deadline: Date.now() + BOOT_TIMEOUT_MS,
      expectedGeneration: null,
      operation: 'starting',
    };
    setIsBooting(true);
    setRuntimeReady(false);
    setBootOperation('starting');
    setBootProgress(5);
    setLabTimer(0);
    setNodeStatuses({});
    setLinkStatus([]);

    try {
      const response = await api.startSession(slug);
      if (!mountedRef.current || operationTokenRef.current !== operationToken) return;
      if (!isValidSessionId(response?.session_id)) throw new Error('Server response did not include a valid session ID');

      const nextGeneration = extractGeneration(response);
      generationRef.current = nextGeneration;
      setGeneration(nextGeneration);
      bootRef.current.expectedGeneration = nextGeneration;
      setBootProgress(extractProgress(response) ?? 15);

      const nextSession = makeStoredSession(response, slug, nextGeneration);
      commitSession(nextSession);
      if (lab?.nodes?.length > 0) setActiveTerminal(lab.nodes[0].name);
      try {
        localStorage.setItem(`netlabx_tasks_${response.session_id}`, JSON.stringify([]));
      } catch {
        // Ignore unavailable storage.
      }
      setStatusCycle(value => value + 1);
    } catch (error) {
      if (!mountedRef.current || operationTokenRef.current !== operationToken) return;
      bootRef.current = { active: false, deadline: 0, expectedGeneration: null, operation: null };
      setIsBooting(false);
      setRuntimeReady(false);
      setBootOperation(null);
      setBootProgress(0);
      setErrorMsg(`Failed to start Native Simulation: ${error.message}`);
    }
  };

  const handleStop = async () => {
    const activeSession = sessionRef.current;
    if (!activeSession) return;
    const operationToken = ++operationTokenRef.current;
    statusPollTokenRef.current += 1;
    clearError();
    bootRef.current = { active: false, deadline: 0, expectedGeneration: null, operation: null };
    setIsBooting(false);
    setRuntimeReady(false);
    setBootOperation(null);
    closeAllSockets(true);

    try {
      await api.stopSession(activeSession.session_id);
      if (!mountedRef.current || operationTokenRef.current !== operationToken) return;
      clearSessionLocally(activeSession.session_id);
    } catch (error) {
      if (!mountedRef.current || operationTokenRef.current !== operationToken) return;
      setErrorMsg(`Failed to stop Native Simulation: ${error.message}. The session was kept so you can retry.`);
      setStatusCycle(value => value + 1);
    }
  };

  const handleGrade = async () => {
    const activeSession = sessionRef.current;
    if (!activeSession) return;
    clearError();
    setIsGrading(true);
    try {
      const startTime = Date.now();
      const report = await api.gradeSession(activeSession.session_id);
      const elapsed = Date.now() - startTime;
      if (elapsed < 1500) {
        await new Promise(resolve => setTimeout(resolve, 1500 - elapsed));
      }
      if (!mountedRef.current || sessionRef.current?.session_id !== activeSession.session_id) return;

      setGradeReport(report);
      if (report.passed) {
        // The result is stored with the account on the server (see /api/progress).
        setShowCompletionModal(true);
      } else {
        // Open the first unfinished task so its findings are visible.
        const firstFailed = (report.tasks || []).find(
          task => task.graded && !task.passed && task.id !== null && task.id !== undefined
        );
        if (firstFailed) setVisibleAnswers({ [firstFailed.id]: true });
        setShowFailModal(true);
      }
    } catch (error) {
      if (mountedRef.current) setErrorMsg(`Grading failed: ${error.message}`);
    } finally {
      if (mountedRef.current) setIsGrading(false);
    }
  };

  const handleReset = async () => {
    const activeSession = sessionRef.current;
    if (!activeSession) return;
    const operationToken = ++operationTokenRef.current;
    statusPollTokenRef.current += 1;
    clearError();
    setShowResetModal(false);
    closeAllSockets(true);
    bootRef.current = {
      active: true,
      deadline: Date.now() + BOOT_TIMEOUT_MS,
      expectedGeneration: null,
      operation: 'resetting',
    };
    setRuntimeReady(false);
    setIsBooting(true);
    setBootOperation('resetting');
    setBootProgress(5);
    setSocketCycle(value => value + 1);

    try {
      const response = await api.resetSession(activeSession.session_id);
      if (!mountedRef.current || operationTokenRef.current !== operationToken) return;
      const nextGeneration = extractGeneration(response);
      bootRef.current.expectedGeneration = nextGeneration;
      if (nextGeneration != null) {
        generationRef.current = nextGeneration;
        setGeneration(nextGeneration);
        commitSession(makeStoredSession(activeSession, slug, nextGeneration));
      }
      setBootProgress(extractProgress(response) ?? 15);
      setTaskProgress([]);
      setPassedTaskIds([]);
      setGradeReport(null);
      try {
        localStorage.setItem(`netlabx_tasks_${activeSession.session_id}`, JSON.stringify([]));
      } catch {
        // Ignore unavailable storage.
      }
      setStatusCycle(value => value + 1);
    } catch (error) {
      if (!mountedRef.current || operationTokenRef.current !== operationToken) return;
      bootRef.current = { active: false, deadline: 0, expectedGeneration: null, operation: null };
      setIsBooting(false);
      setBootOperation(null);
      setRuntimeReady(false);
      setErrorMsg(`Reset failed: ${error.message}`);
      setStatusCycle(value => value + 1);
    }
  };

  return {
    lab, allLabs, session, loading, errorMsg, clearError,
    activeTerminal, setActiveTerminal,
    isGrading, gradeReport,
    visibleHints, setVisibleHints,
    visibleAnswers, setVisibleAnswers,
    showCompletionModal, setShowCompletionModal,
    showFailModal, setShowFailModal,
    showResetModal, setShowResetModal,
    labTimer, isBooting, bootProgress, bootOperation,
    linkStatus, nodeStatuses, terminalStatuses, generation,
    isReady: runtimeReady,
    termFontSize, setTermFontSize,
    taskProgress, passedTaskIds,
    wsRefs, bufRefs, socketCycle,
    handleStart, handleStop, handleGrade, handleReset,
  };
}
