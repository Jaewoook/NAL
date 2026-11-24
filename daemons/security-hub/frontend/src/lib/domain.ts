import type { ManagedItem, TabType } from '../types';

/**
 * Validates that an external link uses an HTTP/HTTPS URL scheme.
 */
export function isSafeHttpUrl(u?: string): boolean {
  return /^https?:\/\//i.test(String(u || '').trim());
}

/**
 * Determines whether a task ID represents a persisted DB task whose logs can be streamed via SSE.
 */
export function isStreamableScanTaskId(
  taskId: string | undefined,
  failedStreamTaskIds: Set<string>
): boolean {
  if (!taskId) return false;
  const id = String(taskId);
  if (id.startsWith('scan_') || id.startsWith('task_')) return false;
  return !failedStreamTaskIds.has(id);
}

/**
 * Checks case-insensitively whether a node name appears in the active scanning node list.
 */
export function isNodeScanningName(scanningNodes: string[], nodeName: string): boolean {
  const target = String(nodeName || '')
    .trim()
    .toLowerCase();
  if (!target) return false;
  return scanningNodes.some((n) => String(n).trim().toLowerCase() === target);
}

/**
 * Removes a node name (case-insensitively) from a scanning list, returning the same array reference if unchanged.
 */
export function removeScanningNodeName(scanningNodes: string[], nodeName: string): string[] {
  const target = String(nodeName || '')
    .trim()
    .toLowerCase();
  if (!target) return scanningNodes;
  const next = scanningNodes.filter((n) => String(n).trim().toLowerCase() !== target);
  return next.length === scanningNodes.length ? scanningNodes : next;
}

/**
 * Extracts the node name that finished scanning (or failed reachability) from a scan stream log line.
 */
export function parseCompletedScanNode(lineText: string, hubNode: string): string | null {
  if (/^\[Hub\] Scanned \d+ local\b/.test(lineText)) {
    return hubNode || 'local';
  }
  const m = lineText.match(/^\[([^\]]+)\] (?:Scanned \d+ remote\b|Remote agent unreachable\b)/);
  return m?.[1] ?? null;
}

/**
 * Returns the sort priority rank (lower is more severe) for items table ordering.
 */
export function getItemSortRank(item: ManagedItem): number {
  if (item.crit_count > 0 || item.broken_linkage || (item.eol && item.eol.status === 'expired')) {
    return 0;
  }
  if (item.high_count > 0 || (item.eol && item.eol.status === 'expiring_soon')) {
    return 1;
  }
  if (item.outdated) {
    return 2;
  }
  return 3;
}

/**
 * Builds a stable identifier key for an item across a node and target type.
 */
export function getItemKey(item: ManagedItem, hubNode: string): string {
  const nodeName = item.node || hubNode || 'local';
  return `${nodeName}:${item.target_type}:${item.name}`;
}

/**
 * Resolves available version tags and the effective selected target version for an item row.
 */
export function resolveTargetVersion(
  item: ManagedItem,
  chosenVersion?: string
): { tags: string[]; selectedVer: string } {
  const rawTags =
    item.available_tags && item.available_tags.length > 0
      ? item.available_tags
      : [item.latest_version || item.current_version];
  const tags = Array.from(new Set(rawTags));
  const defaultVer = tags.includes(item.latest_version) ? item.latest_version : tags[0] || '';
  const selectedVer = chosenVersion && tags.includes(chosenVersion) ? chosenVersion : defaultVer;
  return { tags, selectedVer };
}

/**
 * Checks whether a managed item belongs to a given dashboard inventory tab.
 */
export function matchesDashboardTab(item: ManagedItem, tab: Exclude<TabType, 'logs'>): boolean {
  if (tab === 'docker') return item.target_type === 'docker';
  if (tab === 'brew') return item.target_type === 'brew' || item.target_type === 'apt';
  return item.target_type === 'daemon' || item.target_type === 'macos';
}
