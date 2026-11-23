import axios from 'axios';
import { useCallback, useEffect, useRef, useState } from 'react';
import { getAxiosErrorMessage, hubApi, isAxiosUnauthorized } from '../lib/http';

export type TestFeedback =
  | { kind: 'info'; text: string }
  | { kind: 'ok'; latency?: string; osVersion: string }
  | { kind: 'error'; text: string };

interface UseNodeConnectionTestOptions {
  open: boolean;
  onAutoFillName: (discoveredName: string) => void;
  onUnauthorized?: () => void;
}

/**
 * Manages remote LAN agent connectivity probes with automatic `AbortController` cancellation.
 */
export function useNodeConnectionTest({
  open,
  onAutoFillName,
  onUnauthorized,
}: UseNodeConnectionTestOptions) {
  const [testing, setTesting] = useState(false);
  const [testFeedback, setTestFeedback] = useState<TestFeedback | null>(null);
  const abortControllerRef = useRef<AbortController | null>(null);

  const resetTest = useCallback(() => {
    abortControllerRef.current?.abort();
    abortControllerRef.current = null;
    setTesting(false);
    setTestFeedback(null);
  }, []);

  useEffect(() => {
    if (!open) {
      resetTest();
    }
  }, [open, resetTest]);

  useEffect(() => () => abortControllerRef.current?.abort(), []);

  const runTest = useCallback(
    async (rawUrl: string, rawToken: string) => {
      const trimmedUrl = rawUrl.trim();
      const trimmedToken = rawToken.trim();
      if (!trimmedUrl) {
        abortControllerRef.current?.abort();
        abortControllerRef.current = null;
        setTesting(false);
        setTestFeedback({ kind: 'error', text: 'Please provide the LAN Agent URL to test.' });
        return;
      }

      abortControllerRef.current?.abort();
      const controller = new AbortController();
      abortControllerRef.current = controller;

      setTesting(true);
      setTestFeedback({ kind: 'info', text: `Connecting to ${trimmedUrl}...` });

      try {
        const res = await hubApi.testNodeConnection(trimmedUrl, trimmedToken, controller.signal);
        if (controller.signal.aborted) return;

        const data = res.data;
        if (!data || typeof data !== 'object') {
          setTestFeedback({
            kind: 'error',
            text: `Connection failed: ${res.statusText || `HTTP ${res.status}`}`,
          });
          return;
        }
        if (data.ok) {
          const osVersion = data.os_version || data.info?.os_version || 'Unknown OS';
          const latency = data.latency_ms !== undefined ? `${data.latency_ms}ms` : '';
          setTestFeedback({ kind: 'ok', latency, osVersion });
          if (data.info?.name) {
            onAutoFillName(data.info.name);
          }
        } else {
          setTestFeedback({
            kind: 'error',
            text: `Connection failed: ${data.error || 'Agent unreachable'}`,
          });
        }
      } catch (err) {
        if (controller.signal.aborted || axios.isCancel(err)) return;
        if (isAxiosUnauthorized(err)) {
          onUnauthorized?.();
          return;
        }
        setTestFeedback({
          kind: 'error',
          text: `Connection failed: ${getAxiosErrorMessage(err, 'Agent unreachable')}`,
        });
      } finally {
        if (abortControllerRef.current === controller) {
          abortControllerRef.current = null;
          setTesting(false);
        }
      }
    },
    [onAutoFillName, onUnauthorized]
  );

  return {
    testing,
    testFeedback,
    runTest,
    resetTest,
  };
}
