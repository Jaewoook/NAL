import { useQueryClient } from '@tanstack/react-query';
import { type MutableRefObject, useCallback, useEffect, useRef, useState } from 'react';
import { toast } from 'sonner';
import { isStreamableScanTaskId, removeScanningNodeName } from '../lib/domain';
import { getAxiosErrorMessage, hubApi, isAxiosUnauthorized } from '../lib/http';
import { subscribeTaskSSE } from '../lib/sse';
import type { DashboardResponse, NodeInfo } from '../types';

interface UseScanStreamOptions {
  authenticated: boolean;
  dashboardData: DashboardResponse | null;
  approvedNodes: NodeInfo[];
  authEpochRef: MutableRefObject<number>;
  onPollFallbackChange: (enabled: boolean) => void;
  onUnauthorized: () => void;
  refreshDashboard: () => Promise<void>;
}

/**
 * Coordinates full-cluster and single-node security scan triggers, SSE progress streaming, and polling fallback.
 */
export function useScanStream({
  authenticated,
  dashboardData,
  approvedNodes,
  authEpochRef,
  onPollFallbackChange,
  onUnauthorized,
  refreshDashboard,
}: UseScanStreamOptions) {
  const queryClient = useQueryClient();
  const [scanningNodes, setScanningNodes] = useState<string[]>([]);
  const [isScanActive, setIsScanActive] = useState(false);
  const [scanProgressText, setScanProgressText] = useState('');

  const activeScanSubscriptionRef = useRef<{ close: () => void } | null>(null);
  const failedStreamTaskIdsRef = useRef<Set<string>>(new Set());
  const hubNodeRef = useRef<string>('local');

  useEffect(() => {
    hubNodeRef.current = dashboardData?.hub_node || 'local';
  }, [dashboardData]);

  const closeScanStream = useCallback(() => {
    if (activeScanSubscriptionRef.current) {
      activeScanSubscriptionRef.current.close();
      activeScanSubscriptionRef.current = null;
    }
  }, []);

  const resetScanState = useCallback(() => {
    closeScanStream();
    failedStreamTaskIdsRef.current.clear();
    onPollFallbackChange(false);
    setScanningNodes([]);
    setIsScanActive(false);
    setScanProgressText('');
  }, [closeScanStream, onPollFallbackChange]);

  useEffect(() => closeScanStream, [closeScanStream]);

  const attachScanStream = useCallback(
    (taskId: string) => {
      onPollFallbackChange(false);
      closeScanStream();
      setIsScanActive(true);
      setScanProgressText((prev) => prev || 'Scanning in progress...');

      if (!isStreamableScanTaskId(taskId, failedStreamTaskIdsRef.current)) {
        onPollFallbackChange(true);
        return;
      }

      const epoch = authEpochRef.current;
      const sub = subscribeTaskSSE({
        taskId,
        isValidEpoch: () => epoch === authEpochRef.current,
        onMessage: (event) => {
          failedStreamTaskIdsRef.current.delete(String(taskId));
          const lineText = event.kind === 'structured' ? event.payload.line : event.text;
          if (!lineText) return;

          setScanProgressText(lineText);
          const hubName = hubNodeRef.current || 'local';
          if (/^\[Hub\] Scanned \d+ local\b/.test(lineText)) {
            setScanningNodes((prev) =>
              prev.length > 1 ? removeScanningNodeName(prev, hubName) : prev
            );
          } else {
            const m = lineText.match(
              /^\[([^\]]+)\] (?:Scanned \d+ remote\b|Remote agent unreachable\b)/
            );
            if (m?.[1]) {
              const finishedNode = m[1];
              setScanningNodes((prev) =>
                prev.length > 1 ? removeScanningNodeName(prev, finishedNode) : prev
              );
            }
          }
        },
        onDone: () => {
          if (activeScanSubscriptionRef.current === sub) {
            activeScanSubscriptionRef.current = null;
          }
          onPollFallbackChange(false);
          setScanningNodes([]);
          setIsScanActive(false);
          setScanProgressText('');
          queryClient.setQueryData<DashboardResponse>(['dashboard'], (prev) =>
            prev ? { ...prev, scanning: false, scanning_nodes: [] } : prev
          );
          void refreshDashboard();
        },
        onError: () => {
          if (activeScanSubscriptionRef.current === sub) {
            activeScanSubscriptionRef.current = null;
          }
          failedStreamTaskIdsRef.current.add(String(taskId));
          onPollFallbackChange(true);
        },
      });
      activeScanSubscriptionRef.current = sub;
    },
    [authEpochRef, closeScanStream, onPollFallbackChange, queryClient, refreshDashboard]
  );

  useEffect(() => {
    if (!authenticated || !dashboardData) return;
    if (dashboardData.scanning) {
      setScanningNodes(
        Array.isArray(dashboardData.scanning_nodes) ? dashboardData.scanning_nodes : []
      );
      setIsScanActive(true);
      const activeId = dashboardData.active_scan_task_id;
      if (!activeScanSubscriptionRef.current) {
        if (activeId && isStreamableScanTaskId(activeId, failedStreamTaskIdsRef.current)) {
          attachScanStream(activeId);
        } else {
          setScanProgressText((prev) => prev || 'Scanning in progress...');
          onPollFallbackChange(true);
        }
      }
    } else if (!activeScanSubscriptionRef.current) {
      onPollFallbackChange(false);
      setScanningNodes([]);
      setIsScanActive(false);
      setScanProgressText('');
    }
  }, [authenticated, dashboardData, attachScanStream, onPollFallbackChange]);

  const triggerScan = useCallback(
    async (targetNode = '') => {
      const epoch = authEpochRef.current;
      onPollFallbackChange(false);
      setIsScanActive(true);
      setScanningNodes(targetNode ? [targetNode] : approvedNodes.map((n) => n.name));
      setScanProgressText(
        targetNode
          ? `Initializing scan for [${targetNode}]...`
          : 'Initializing full security scan...'
      );

      try {
        const res = await hubApi.triggerScan(targetNode);
        if (epoch !== authEpochRef.current) return;

        const data = res.data || {};
        if (
          Array.isArray(data.scanning_nodes) &&
          (res.status === 409 || data.scanning_nodes.length > 0)
        ) {
          setScanningNodes(data.scanning_nodes);
        }
        if (res.status === 409) {
          setScanProgressText('Scan in progress; attaching to stream...');
        }
        if (!data.task_id) {
          setScanningNodes([]);
          setIsScanActive(false);
          setScanProgressText('');
          await refreshDashboard();
          return;
        }

        attachScanStream(data.task_id);
      } catch (err) {
        if (epoch !== authEpochRef.current) return;
        if (isAxiosUnauthorized(err)) {
          onUnauthorized();
          return;
        }
        toast.error(`Scan failed: ${getAxiosErrorMessage(err)}`);
        setScanningNodes([]);
        setIsScanActive(false);
        setScanProgressText('');
      }
    },
    [
      approvedNodes,
      attachScanStream,
      authEpochRef,
      onPollFallbackChange,
      onUnauthorized,
      refreshDashboard,
    ]
  );

  return {
    scanningNodes,
    scanProgressText,
    effectiveScanActive:
      isScanActive || Boolean(dashboardData?.scanning) || scanningNodes.length > 0,
    triggerScan,
    resetScanState,
  };
}
