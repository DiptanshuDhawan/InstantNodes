import React from 'react';
import dynamic from 'next/dynamic';
import { classifyNode } from '@/lib/nodeClassification';

const Terminal = dynamic(() => import('@/components/Terminal'), { ssr: false });

const SidebarRouterIcon = () => (
  <svg width="18" height="18" viewBox="-42 -30 84 60">
    <path d="M-38,-10 v22 a38,14 0 0,0 76,0 v-22 Z" fill="#222428" stroke="#9ca3af" strokeWidth="4" />
    <ellipse cx="0" cy="-10" rx="38" ry="14" fill="#2A2D32" stroke="#9ca3af" strokeWidth="4" />
    <g stroke="#E2E8F0" strokeWidth="4" fill="none" strokeLinecap="round" strokeLinejoin="round">
      <path d="M-4,-10 L-15,-10 M-11,-14 L-15,-10 L-11,-6" />
      <path d="M4,-10 L15,-10 M11,-14 L15,-10 L11,-6" />
      <path d="M0,-21 L0,-14 M-4,-18 L0,-14 L4,-18" />
      <path d="M0,1 L0,-6 M-4,-2 L0,-6 L4,-2" />
    </g>
  </svg>
);

const SidebarSwitchIcon = () => (
  <svg width="18" height="18" viewBox="-42 -30 84 60">
    <path d="M -38 0 L 18 0 L 18 20 L -38 20 Z" fill="#222428" stroke="#9ca3af" strokeWidth="4" strokeLinejoin="round"/>
    <path d="M -38 0 L -18 -22 L 38 -22 L 18 0 Z" fill="#2A2D32" stroke="#9ca3af" strokeWidth="4" strokeLinejoin="round"/>
    <path d="M 18 0 L 38 -22 L 38 -2 L 18 20 Z" fill="#1A1C1E" stroke="#9ca3af" strokeWidth="4" strokeLinejoin="round"/>
    <g stroke="#E2E8F0" strokeWidth="3.5" fill="none" strokeLinecap="round" strokeLinejoin="round">
      <path d="M -12 -15 L 12 -15 M 6 -19 L 12 -15 L 6 -11" />
      <path d="M -12 -7 L 12 -7 M -6 -11 L -12 -7 L -6 -3" />
    </g>
  </svg>
);

const SidebarPCIcon = () => (
  <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#9ca3af" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="4" width="20" height="13" rx="2" ry="2" fill="#222428"/>
    <path d="M8 20h8 M12 17v3" />
  </svg>
);

function NodeIcon({ node }) {
  const kind = classifyNode(node);
  if (kind === 'switch') return <SidebarSwitchIcon />;
  if (kind === 'host') return <SidebarPCIcon />;
  return <SidebarRouterIcon />;
}

function bootLabel(operation) {
  if (operation === 'resetting') return 'RESETTING NATIVE SIMULATION';
  if (operation === 'restoring') return 'RESTORING NATIVE SIMULATION';
  if (operation === 'reconnecting') return 'RECONNECTING NATIVE SIMULATION';
  return 'STARTING NATIVE SIMULATION';
}

export default function TerminalPanel({
  lab, session, isBooting, bootProgress, bootOperation, isReady,
  terminalStatuses,
  activeTerminal, setActiveTerminal,
  termFontSize, setTermFontSize,
  wsRefs, bufRefs,
}) {
  const nodes = lab?.nodes?.map(node => node.name) || [];
  const runtimeIsReady = isReady ?? Boolean(session && !isBooting);
  const activeTerminalStatus = terminalStatuses?.[activeTerminal];
  const terminalIsConnecting = session && runtimeIsReady && activeTerminal && activeTerminalStatus !== 'connected';

  return (
    <div className="nx-term-panel nx-card" style={{ padding: 0 }}>
      <div className="nx-term-tabs" style={{ display: 'flex', justifyContent: 'space-between', paddingRight: '12px', alignItems: 'center' }}>
        <div style={{ display: 'flex', gap: '4px' }}>
          {lab?.nodes?.map(node => (
            <button
              key={node.name}
              className={`nx-term-tab ${activeTerminal === node.name ? 'active' : ''}`}
              onClick={() => setActiveTerminal(node.name)}
              disabled={!session || isBooting || !runtimeIsReady}
            >
              <span className="tab-icon"><NodeIcon node={node} /></span>
              {node.name}
            </button>
          ))}
        </div>

        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <button
            className="nx-btn"
            style={{ padding: '4px 8px', background: 'transparent', border: '1px solid rgba(255,255,255,0.1)', color: 'var(--text-muted)' }}
            onClick={() => setTermFontSize(fontSize => Math.max(12, fontSize - 2))}
            title="Decrease Font Size"
          >
            A-
          </button>
          <button
            className="nx-btn"
            style={{ padding: '4px 8px', background: 'transparent', border: '1px solid rgba(255,255,255,0.1)', color: 'var(--text-muted)' }}
            onClick={() => setTermFontSize(fontSize => Math.min(24, fontSize + 2))}
            title="Increase Font Size"
          >
            A+
          </button>
        </div>
      </div>
      <div className="nx-term-body">
        {!session || isBooting || !runtimeIsReady ? (
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', backgroundColor: 'var(--bg-base)' }}>
            {isBooting ? (
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, color: 'var(--text-muted)' }}>
                <svg className="nx-spin" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                  <path d="M21 12a9 9 0 1 1-6.219-8.56" />
                </svg>
                <span style={{ fontSize: 13, letterSpacing: '0.5px' }}>{bootLabel(bootOperation)}... {bootProgress}%</span>
              </div>
            ) : (
              <>
                <div style={{ width: 64, height: 64, borderRadius: '50%', background: 'rgba(255,255,255,0.03)', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: 20 }}>
                  <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#4b5563" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="2" y="4" width="20" height="16" rx="3" ry="3"/>
                    <polyline points="7 10 10 13 7 16"/>
                    <line x1="12" y1="16" x2="16" y2="16"/>
                  </svg>
                </div>
                <div style={{ color: 'var(--text-secondary)', fontSize: 14, letterSpacing: '0.5px', marginBottom: 6 }}>
                  {session ? 'NATIVE SIMULATION UNAVAILABLE' : 'ENVIRONMENT OFFLINE'}
                </div>
                <div style={{ color: 'var(--text-muted)', fontSize: 13, letterSpacing: '0.5px' }}>
                  {session ? 'RESET OR STOP THE SESSION TO RECOVER' : 'SELECT START LAB TO LAUNCH THE NATIVE SIMULATION'}
                </div>
              </>
            )}
          </div>
        ) : (
          <>
            {nodes.map(node => (
              <div key={node} style={{ display: activeTerminal === node ? 'block' : 'none', height: '100%' }}>
                <Terminal ws={wsRefs.current[node]} buffer={bufRefs.current[node]} nodeName={node} fontSize={termFontSize} />
              </div>
            ))}
            {terminalIsConnecting && (
              <div
                role="status"
                style={{ position: 'absolute', top: 12, right: 16, zIndex: 5, padding: '6px 10px', borderRadius: 6, border: '1px solid rgba(245, 158, 11, 0.35)', background: 'rgba(20, 21, 23, 0.9)', color: 'var(--warning, #f59e0b)', fontSize: 11, letterSpacing: '0.5px' }}
              >
                {activeTerminalStatus === 'failed'
                  ? 'TERMINAL CONNECTION REJECTED'
                  : activeTerminalStatus === 'disconnected'
                    ? 'TERMINAL DISCONNECTED — RETRYING...'
                    : 'RECONNECTING TERMINAL...'}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
