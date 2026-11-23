import { type MutableRefObject, useCallback, useEffect, useRef, useState } from 'react';
import { subscribeTaskSSE } from '../lib/sse';
import type { RenderedLogEntry } from '../types';

interface UseTaskLogStreamOptions {
  authEpochRef: MutableRefObject<number>;
  refreshDashboard: () => Promise<void>;
}

/**
 * Manages live SSE stdout/stderr streaming for a selected task in the Audit Console.
 */
export function useTaskLogStream({ authEpochRef, refreshDashboard }: UseTaskLogStreamOptions) {
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
            setTaskLogLines((prev) => [
              ...prev,
              {
                key: entryKey,
                loggedAt: event.payload.logged_at,
                stream: event.payload.stream,
                line: event.payload.line,
              },
            ]);
          } else {
            setTaskLogLines((prev) => [
              ...prev,
              { key: entryKey, line: event.text, rawText: true },
            ]);
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
