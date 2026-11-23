import type { TaskLogLine } from '../types';
import { hubApi } from './http';

export type ParsedTaskStreamEvent =
  | { kind: 'structured'; payload: TaskLogLine }
  | { kind: 'raw'; text: string };

/**
 * Parses an SSE `MessageEvent` payload emitted by `/api/tasks/:id/stream`.
 */
export function parseTaskStreamMessage(raw: unknown): ParsedTaskStreamEvent {
  if (typeof raw === 'string') {
    try {
      const parsed = JSON.parse(raw) as Partial<TaskLogLine>;
      if (parsed && typeof parsed === 'object' && typeof parsed.line === 'string') {
        return {
          kind: 'structured',
          payload: {
            task_id: parsed.task_id,
            seq: parsed.seq,
            logged_at: parsed.logged_at || '',
            stream: parsed.stream || 'info',
            line: parsed.line,
          },
        };
      }
    } catch {
      // Fall back to raw text when SSE line is unformatted plain text.
    }
    return { kind: 'raw', text: raw };
  }
  return { kind: 'raw', text: '' };
}

export interface SubscribeTaskSSEOptions {
  taskId: string;
  isValidEpoch: () => boolean;
  onMessage: (event: ParsedTaskStreamEvent) => void;
  onDone?: () => void;
  onError?: () => void;
}

/**
 * Opens a managed `EventSource` subscription for a task log stream and returns an idempotent close handle.
 */
export function subscribeTaskSSE({
  taskId,
  isValidEpoch,
  onMessage,
  onDone,
  onError,
}: SubscribeTaskSSEOptions): { close: () => void } {
  let closed = false;
  const es = new EventSource(hubApi.taskStreamUrl(taskId));

  const close = () => {
    if (closed) return;
    closed = true;
    es.close();
  };

  es.onmessage = (e: MessageEvent) => {
    if (closed || !isValidEpoch()) return;
    onMessage(parseTaskStreamMessage(e.data));
  };

  es.addEventListener('done', () => {
    if (closed) return;
    close();
    if (!isValidEpoch()) return;
    onDone?.();
  });

  es.onerror = () => {
    if (closed) return;
    close();
    if (!isValidEpoch()) return;
    onError?.();
  };

  return { close };
}
