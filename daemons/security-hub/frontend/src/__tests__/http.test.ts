import type { InternalAxiosRequestConfig } from 'axios';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cn } from '../lib/cn';
import { apiClient, setCsrfToken } from '../lib/http';
import { parseTaskStreamMessage } from '../lib/sse';

describe('frontend cn, http, and sse helpers', () => {
  afterEach(() => {
    setCsrfToken('');
    vi.restoreAllMocks();
  });

  it('merges conditional Tailwind classes cleanly via cn', () => {
    expect(cn('px-4 py-2', false && 'hidden', 'px-2')).toBe('py-2 px-2');
  });

  it('parses structured JSON and plain text SSE log lines', () => {
    const structured = parseTaskStreamMessage(
      JSON.stringify({ logged_at: '2026-11-24T00:00:00Z', stream: 'cmd', line: 'docker pull' })
    );
    expect(structured).toEqual({
      kind: 'structured',
      payload: {
        task_id: undefined,
        seq: undefined,
        logged_at: '2026-11-24T00:00:00Z',
        stream: 'cmd',
        line: 'docker pull',
      },
    });
    expect(parseTaskStreamMessage('plain output')).toEqual({ kind: 'raw', text: 'plain output' });
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
