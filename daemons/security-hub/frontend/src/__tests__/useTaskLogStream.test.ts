import { act, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { MAX_TASK_LOG_LINES, useTaskLogStream } from '../hooks/useTaskLogStream';
import * as sseModule from '../lib/sse';

describe('useTaskLogStream', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('caps buffered log lines at MAX_TASK_LOG_LINES and resets on authEpoch change', () => {
    const close = vi.fn();
    let emitMessage: ((event: sseModule.ParsedTaskStreamEvent) => void) | undefined;

    vi.spyOn(sseModule, 'subscribeTaskSSE').mockImplementation((opts) => {
      emitMessage = opts.onMessage;
      return { close };
    });

    const authEpochRef = { current: 0 };
    const refreshDashboard = vi.fn().mockResolvedValue(undefined);

    const { result, rerender } = renderHook(
      ({ authEpoch }) => useTaskLogStream({ authEpoch, authEpochRef, refreshDashboard }),
      { initialProps: { authEpoch: 0 } }
    );

    act(() => {
      result.current.streamTaskLogs('task-42');
    });
    expect(result.current.activeTaskId).toBe('task-42');

    act(() => {
      for (let i = 0; i < MAX_TASK_LOG_LINES + 5; i += 1) {
        emitMessage?.({ kind: 'raw', text: `line-${i}` });
      }
    });

    expect(result.current.taskLogLines).toHaveLength(MAX_TASK_LOG_LINES);
    expect(result.current.taskLogLines[0].line).toBe('line-5');
    expect(result.current.taskLogLines[MAX_TASK_LOG_LINES - 1].line).toBe(
      `line-${MAX_TASK_LOG_LINES + 4}`
    );

    authEpochRef.current = 1;
    rerender({ authEpoch: 1 });

    expect(close).toHaveBeenCalledTimes(1);
    expect(result.current.activeTaskId).toBe('');
    expect(result.current.taskLogLines).toEqual([]);
  });
});
