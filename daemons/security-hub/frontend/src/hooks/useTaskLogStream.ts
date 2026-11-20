import { useCallback, useEffect, useRef, useState, type MutableRefObject } from 'react';
import type { RenderedLogEntry, TaskLogLine } from '../types';

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
  const activeTaskEventSourceRef = useRef<EventSource | null>(null);
  const logSeqRef = useRef(0);

  const closeTaskStream = useCallback(() => {
    if (activeTaskEventSourceRef.current) {
      activeTaskEventSourceRef.current.close();
      activeTaskEventSourceRef.current = null;
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

      const es = new EventSource(`/api/tasks/${encodeURIComponent(taskId)}/stream`);
      activeTaskEventSourceRef.current = es;

      es.onmessage = (e: MessageEvent) => {
        if (epoch !== authEpochRef.current || activeTaskEventSourceRef.current !== es) return;
        logSeqRef.current += 1;
        const entryKey = `${taskId}-${logSeqRef.current}`;
        try {
          const line = JSON.parse(e.data) as TaskLogLine;
          setTaskLogLines((prev) => [
            ...prev,
            { key: entryKey, loggedAt: line.logged_at, stream: line.stream, line: line.line },
          ]);
        } catch {
          setTaskLogLines((prev) => [
            ...prev,
            { key: entryKey, line: typeof e.data === 'string' ? e.data : '', rawText: true },
          ]);
        }
      };

      es.addEventListener('done', () => {
        if (activeTaskEventSourceRef.current === es) {
          es.close();
          activeTaskEventSourceRef.current = null;
        }
        if (epoch !== authEpochRef.current) return;
        void refreshDashboard();
      });

      es.onerror = () => {
        if (activeTaskEventSourceRef.current === es) {
          es.close();
          activeTaskEventSourceRef.current = null;
        }
      };
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
