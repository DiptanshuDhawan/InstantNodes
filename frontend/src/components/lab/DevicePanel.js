import React, { useState } from 'react';
import { classifyNode, getNodeStatus, isNodeOnline } from '@/lib/nodeClassification';

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

const CATEGORY_CONFIG = [
  { label: 'Routers', kind: 'router', Icon: SidebarRouterIcon },
  { label: 'Switches', kind: 'switch', Icon: SidebarSwitchIcon },
  { label: 'End Hosts', stateKey: 'EndHosts', kind: 'host', Icon: SidebarPCIcon },
];

function NodeStatusDot({ node, nodeStatuses, session, isBooting }) {
  const status = getNodeStatus(nodeStatuses, node.name);
  const hasRuntimeStatuses = nodeStatuses != null;
  const online = hasRuntimeStatuses
    ? isNodeOnline(status)
    : Boolean(session && !isBooting);
  const label = status || (online ? 'online' : 'offline');

  return (
    <div
      className={online ? 'nx-node-online' : 'nx-node-offline'}
      title={`${node.name}: ${label}`}
      aria-label={`${node.name} is ${label}`}
    />
  );
}

export default function DevicePanel({
  lab, session, isBooting, nodeStatuses,
  activeTerminal, setActiveTerminal,
}) {
  const [openCategories, setOpenCategories] = useState({ Routers: true, Switches: true, EndHosts: true });

  const toggleCategory = (category) => {
    setOpenCategories(previous => ({ ...previous, [category]: !previous[category] }));
  };

  const nodes = lab?.nodes || [];

  return (
    <aside className="nx-sidebar-right nx-card">
      <div className="nx-section-header">
        <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '.6px' }}>Devices</span>
      </div>

      <div>
        <div className="nx-right-section-label">Topology Nodes</div>

        {CATEGORY_CONFIG.map(({ label, stateKey = label, kind, Icon }) => {
          const categoryNodes = nodes.filter(node => classifyNode(node) === kind);
          const isOpen = openCategories[stateKey];

          return (
            <div className="nx-device-category" key={stateKey}>
              <div
                className="nx-device-category-header"
                onClick={() => toggleCategory(stateKey)}
                style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 16px', borderBottom: '1px solid var(--border)' }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <div className="nx-right-topo-icon"><Icon /></div>
                  <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{label}</span>
                </div>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ transform: isOpen ? 'rotate(180deg)' : 'none', transition: 'transform 0.2s' }}><polyline points="6 9 12 15 18 9"/></svg>
              </div>

              {isOpen && (
                <div style={{ background: 'var(--bg-lighter)', padding: '8px 0', borderBottom: '1px solid var(--border)' }}>
                  {categoryNodes.length > 0 && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                      {categoryNodes.map(node => (
                        <div
                          key={node.name}
                          className={`nx-node-row ${activeTerminal === node.name ? 'active' : ''}`}
                          onClick={() => setActiveTerminal(node.name)}
                        >
                          <div className="nx-node-icon"><Icon /></div>
                          <span className="nx-node-name">{node.name}</span>
                          <NodeStatusDot
                            node={node}
                            nodeStatuses={nodeStatuses}
                            session={session}
                            isBooting={isBooting}
                          />
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </aside>
  );
}
