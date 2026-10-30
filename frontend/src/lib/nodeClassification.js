const normalizeHint = (value) => String(value || '').trim().toLowerCase().replace(/[\s-]+/g, '_');

function classifyHint(value) {
  const hint = normalizeHint(value);
  if (!hint) return null;

  if (hint.includes('switch') || hint.includes('bridge') || hint === 'l2' || hint.includes('_l2')) {
    return 'switch';
  }
  if (
    hint.includes('host') || hint.includes('endpoint') || hint.includes('client') ||
    hint.includes('server') || hint.includes('linux') || hint.includes('vpcs') ||
    hint === 'pc' || hint.includes('shell')
  ) {
    return 'host';
  }
  if (hint.includes('router') || hint.includes('routing') || hint.includes('ios')) {
    return 'router';
  }

  return null;
}

export function classifyNode(node = {}) {
  const neutralKind = classifyHint(node.kind);
  if (neutralKind) return neutralKind;

  const cliKind = classifyHint(node.cli_profile);
  if (cliKind) return cliKind;

  if (String(node.name || '').toUpperCase().startsWith('PC')) return 'host';

  const legacyKind = classifyHint(node.device_type);
  return legacyKind || 'router';
}

export function getNodeStatus(nodeStatuses, nodeName) {
  if (!nodeStatuses || typeof nodeStatuses !== 'object') return null;
  const direct = nodeStatuses[nodeName];
  const value = direct ?? Object.entries(nodeStatuses)
    .find(([name]) => name.toLowerCase() === String(nodeName).toLowerCase())?.[1];

  if (typeof value === 'boolean') return value ? 'ready' : 'stopped';
  if (value && typeof value === 'object') {
    return String(value.status ?? value.state ?? (value.ready === true ? 'ready' : '')).toLowerCase() || null;
  }
  return value == null ? null : String(value).toLowerCase();
}

export function isNodeOnline(status) {
  return ['ready', 'running', 'started', 'online', 'up', 'active', 'connected', 'booted']
    .includes(String(status || '').toLowerCase());
}
