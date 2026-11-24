import { describe, expect, it } from 'vitest';
import {
  getItemKey,
  getItemSortRank,
  isNodeScanningName,
  isSafeHttpUrl,
  isStreamableScanTaskId,
  parseCompletedScanNode,
  removeScanningNodeName,
  resolveTargetVersion,
} from '../lib/domain';
import type { ManagedItem } from '../types';

describe('domain helpers', () => {
  it('validates safe HTTP/HTTPS URLs only', () => {
    expect(isSafeHttpUrl('https://github.com/org/repo/releases')).toBe(true);
    expect(isSafeHttpUrl('http://192.168.1.50:10247')).toBe(true);
    expect(isSafeHttpUrl('javascript:alert(1)')).toBe(false);
    expect(isSafeHttpUrl('data:text/html,hi')).toBe(false);
    expect(isSafeHttpUrl('')).toBe(false);
  });

  it('identifies streamable scan task IDs', () => {
    const failed = new Set<string>(['42']);
    expect(isStreamableScanTaskId('101', failed)).toBe(true);
    expect(isStreamableScanTaskId('42', failed)).toBe(false);
    expect(isStreamableScanTaskId('scan_12345', failed)).toBe(false);
    expect(isStreamableScanTaskId('task_12345', failed)).toBe(false);
    expect(isStreamableScanTaskId('', failed)).toBe(false);
  });

  it('tracks and removes scanning node names case-insensitively', () => {
    const active = ['Axis', 'Atlas'];
    expect(isNodeScanningName(active, 'atlas')).toBe(true);
    expect(isNodeScanningName(active, 'Aegis')).toBe(false);

    const after = removeScanningNodeName(active, 'ATLAS');
    expect(after).toEqual(['Axis']);
    expect(removeScanningNodeName(after, 'unknown')).toBe(after);
  });

  it('parses completed or unreachable scan node names from log lines', () => {
    expect(parseCompletedScanNode('[Hub] Scanned 18 local packages', 'Axis')).toBe('Axis');
    expect(parseCompletedScanNode('[Hub] Scanned 0 local packages', '')).toBe('local');
    expect(parseCompletedScanNode('[Atlas] Scanned 12 remote packages', 'Axis')).toBe('Atlas');
    expect(
      parseCompletedScanNode('[Aegis] Remote agent unreachable: connection refused', 'Axis')
    ).toBe('Aegis');
    expect(parseCompletedScanNode('[Hub] Starting local inventory...', 'Axis')).toBeNull();
    expect(parseCompletedScanNode('[Atlas] Querying Trivy CVEs...', 'Axis')).toBeNull();
  });

  it('sorts items by severity rank, computes keys, and resolves target version defaults', () => {
    const base: ManagedItem = {
      target_type: 'docker',
      name: 'svc',
      current_version: '1.0',
      latest_version: '1.2',
      available_tags: ['1.1', '1.2'],
      outdated: false,
      skipped: false,
      broken_linkage: false,
      crit_count: 0,
      high_count: 0,
    };

    expect(getItemKey(base, 'Axis')).toBe('Axis:docker:svc');
    expect(getItemKey({ ...base, node: 'Atlas' }, 'Axis')).toBe('Atlas:docker:svc');

    expect(getItemSortRank({ ...base, crit_count: 1 })).toBe(0);
    expect(getItemSortRank({ ...base, broken_linkage: true })).toBe(0);
    expect(getItemSortRank({ ...base, eol: { status: 'expired' } })).toBe(0);
    expect(getItemSortRank({ ...base, high_count: 2 })).toBe(1);
    expect(getItemSortRank({ ...base, eol: { status: 'expiring_soon' } })).toBe(1);
    expect(getItemSortRank({ ...base, outdated: true })).toBe(2);
    expect(getItemSortRank(base)).toBe(3);

    expect(resolveTargetVersion(base)).toEqual({ tags: ['1.1', '1.2'], selectedVer: '1.2' });
    expect(resolveTargetVersion(base, '1.1')).toEqual({
      tags: ['1.1', '1.2'],
      selectedVer: '1.1',
    });
    expect(resolveTargetVersion(base, 'stale-tag')).toEqual({
      tags: ['1.1', '1.2'],
      selectedVer: '1.2',
    });
  });
});
