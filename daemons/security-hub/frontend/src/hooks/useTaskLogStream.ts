import { type MutableRefObject, useCallback, useEffect, useRef, useState } from 'react';
import { subscribeTaskSSE } from '../lib/sse';
import type { RenderedLogEntry } from '../types';

export const MAX_TASK_LOG_LINES = 2000;

function appendBoundedLogEntry(
  prev: RenderedLogEntry[],
  entry: RenderedLogEntry
): RenderedLogEntry[] {
  if (prev.length >= MAX_TASK_LOG_LINES) {
    return [...prev.slice(prev.length - MAX_TASK_LOG_LINES + 1), entry];
  }
  return [...prev, entry];
}

interface UseTaskLogStreamOptions {
  authEpoch: number;
  authEpochRef: MutableRefObject<number>;
  refreshDashboard: () => Promise<void>;
}

/**
 * Manages live SSE stdout/stderr streaming for a selected task in the Audit Console.
 */
export function useTaskLogStream({
  authEpoch,
  authEpochRef,
  refreshDashboard,
}: UseTaskLogStreamOptions) {
  const [activeTaskId, setActiveTaskId] = useState('');
  const [taskLogLines, setTaskLogLines] = useState<RenderedLogEntry[]>([]);
  const activeTaskSubRef = useRef<{ close: () => void } | null>(null);
  const logSeqRef = useRef(0);

  const closeTaskStream = useCallback(() => {
    if (activeTaskSubRef.current) {
      activeTaskSubRef.current.close();
      activeTaskSubRef.current = null;
    }
  }, []);

  const resetTaskLogs = useCallback(() => {
    closeTaskStream();
    setActiveTaskId('');
    setTaskLogLines([]);
  }, [closeTaskStream]);

  useEffect(() => closeTaskStream, [closeTaskStream]);

  useEffect(() => {
    if (authEpoch > 0) {
      resetTaskLogs();
    }
  }, [authEpoch, resetTaskLogs]);

  const streamTaskLogs = useCallback(
    (taskId: string) => {
      closeTaskStream();
      const epoch = authEpochRef.current;
      setActiveTaskId(taskId);
      setTaskLogLines([]);

      const sub = subscribeTaskSSE({
        taskId,
        isValidEpoch: () => epoch === authEpochRef.current,
        onMessage: (event) => {
          logSeqRef.current += 1;
          const entryKey = `${taskId}-${logSeqRef.current}`;
          if (event.kind === 'structured') {
            setTaskLogLines((prev) =>
              appendBoundedLogEntry(prev, {
                key: entryKey,
                loggedAt: event.payload.logged_at,
                stream: event.payload.stream,
                line: event.payload.line,
              })
            );
          } else {
            setTaskLogLines((prev) =>
              appendBoundedLogEntry(prev, { key: entryKey, line: event.text, rawText: true })
            );
          }
        },
        onDone: () => {
          if (activeTaskSubRef.current === sub) {
            activeTaskSubRef.current = null;
          }
          void refreshDashboard();
        },
        onError: () => {
          if (activeTaskSubRef.current === sub) {
            activeTaskSubRef.current = null;
          }
        },
      });
      activeTaskSubRef.current = sub;
    },
    [authEpochRef, closeTaskStream, refreshDashboard]
  );

  return {
    activeTaskId,
    taskLogLines,
    streamTaskLogs,
    resetTaskLogs,
  };
}
