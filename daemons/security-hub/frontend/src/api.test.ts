import { afterEach, describe, expect, it, vi } from 'vitest';
import type { InternalAxiosRequestConfig } from 'axios';
import {
  apiClient,
  cn,
  getItemSortRank,
  isNodeScanningName,
  isSafeHttpUrl,
  isStreamableScanTaskId,
  removeScanningNodeName,
  setCsrfToken,
} from './api';
import type { ManagedItem } from './types';

describe('api helpers', () => {
  afterEach(() => {
    setCsrfToken('');
    document.cookie = 'nal_csrf_token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
    vi.restoreAllMocks();
  });

  it('merges conditional Tailwind classes cleanly via cn', () => {
    expect(cn('px-4 py-2', false && 'hidden', 'px-2')).toBe('py-2 px-2');
  });

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

  it('sorts items by severity rank', () => {
    const base: ManagedItem = {
      target_type: 'docker',
      name: 'svc',
      current_version: '1.0',
      latest_version: '1.0',
      outdated: false,
      skipped: false,
      broken_linkage: false,
      crit_count: 0,
      high_count: 0,
    };
    expect(getItemSortRank({ ...base, crit_count: 1 })).toBe(0);
    expect(getItemSortRank({ ...base, broken_linkage: true })).toBe(0);
    expect(getItemSortRank({ ...base, eol: { status: 'expired' } })).toBe(0);
    expect(getItemSortRank({ ...base, high_count: 2 })).toBe(1);
    expect(getItemSortRank({ ...base, eol: { status: 'expiring_soon' } })).toBe(1);
    expect(getItemSortRank({ ...base, outdated: true })).toBe(2);
    expect(getItemSortRank(base)).toBe(3);
  });

  it('attaches X-CSRF-Token on mutating Axios requests but not GET', async () => {
    setCsrfToken('fallback-csrf-123');
    const captured: InternalAxiosRequestConfig[] = [];
    const mockAdapter = async (config: InternalAxiosRequestConfig) => {
      captured.push(config);
      return { data: {}, status: 200, statusText: 'OK', headers: {}, config };
    };

    await apiClient.get('/api/dashboard', { adapter: mockAdapter });
    expect(captured[0].headers.get('X-CSRF-Token')).toBeUndefined();

    await apiClient.post('/api/scan', { node: 'Atlas' }, { adapter: mockAdapter });
    expect(captured[1].headers.get('X-CSRF-Token')).toBe('fallback-csrf-123');
  });
});
