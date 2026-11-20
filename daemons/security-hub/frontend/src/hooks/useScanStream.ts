import { useCallback, useEffect, useRef, useState, type MutableRefObject } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { toast } from 'sonner';
import {
  apiClient,
  getAxiosErrorMessage,
  isAxiosUnauthorized,
  isStreamableScanTaskId,
  removeScanningNodeName,
} from '../api';
import type { DashboardResponse, NodeInfo, TaskLogLine } from '../types';

interface ScanTriggerResp {
  task_id?: string;
  scanning_nodes?: string[];
}

interface UseScanStreamOptions {
  authenticated: boolean;
  dashboardData: DashboardResponse | null;
  approvedNodes: NodeInfo[];
  authEpochRef: MutableRefObject<number>;
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
  onUnauthorized,
  refreshDashboard,
}: UseScanStreamOptions) {
  const queryClient = useQueryClient();
  const [scanningNodes, setScanningNodes] = useState<string[]>([]);
  const [isScanActive, setIsScanActive] = useState(false);
  const [scanProgressText, setScanProgressText] = useState('');
  const [pollFallback, setPollFallback] = useState(false);

  const activeScanEventSourceRef = useRef<EventSource | null>(null);
  const failedStreamTaskIdsRef = useRef<Set<string>>(new Set());
  const hubNodeRef = useRef<string>('local');

  useEffect(() => {
    hubNodeRef.current = dashboardData?.hub_node || 'local';
  }, [dashboardData]);

  const closeScanStream = useCallback(() => {
    if (activeScanEventSourceRef.current) {
      activeScanEventSourceRef.current.close();
      activeScanEventSourceRef.current = null;
    }
  }, []);

  const resetScanState = useCallback(() => {
    closeScanStream();
    failedStreamTaskIdsRef.current.clear();
    setPollFallback(false);
    setScanningNodes([]);
    setIsScanActive(false);
    setScanProgressText('');
  }, [closeScanStream]);

  useEffect(() => closeScanStream, [closeScanStream]);

  const attachScanStream = useCallback(
    (taskId: string) => {
      setPollFallback(false);
      closeScanStream();
      setIsScanActive(true);
      setScanProgressText((prev) => prev || 'Scanning in progress...');

      if (!isStreamableScanTaskId(taskId, failedStreamTaskIdsRef.current)) {
        setPollFallback(true);
        return;
      }

      const epoch = authEpochRef.current;
      const es = new EventSource(`/api/tasks/${encodeURIComponent(taskId)}/stream`);
      activeScanEventSourceRef.current = es;

      es.onmessage = (e: MessageEvent) => {
        if (epoch !== authEpochRef.current || activeScanEventSourceRef.current !== es) return;
        failedStreamTaskIdsRef.current.delete(String(taskId));

        let lineText = '';
        try {
          const parsed = JSON.parse(e.data) as Partial<TaskLogLine>;
          lineText = parsed.line || '';
        } catch {
          lineText = typeof e.data === 'string' ? e.data : '';
        }

        if (lineText) {
          setScanProgressText(lineText);
          const hubName = hubNodeRef.current || 'local';
          if (/^\[Hub\] Scanned \d+ local\b/.test(lineText)) {
            setScanningNodes((prev) => (prev.length > 1 ? removeScanningNodeName(prev, hubName) : prev));
          } else {
            const m = lineText.match(/^\[([^\]]+)\] (?:Scanned \d+ remote\b|Remote agent unreachable\b)/);
            if (m && m[1]) {
              const finishedNode = m[1];
              setScanningNodes((prev) =>
                prev.length > 1 ? removeScanningNodeName(prev, finishedNode) : prev
              );
            }
          }
        }
      };

      es.addEventListener('done', () => {
        if (activeScanEventSourceRef.current !== es) return;
        es.close();
        activeScanEventSourceRef.current = null;
        if (epoch !== authEpochRef.current) return;
        setPollFallback(false);
        setScanningNodes([]);
        setIsScanActive(false);
        setScanProgressText('');
        queryClient.setQueryData<DashboardResponse>(['dashboard'], (prev) =>
          prev ? { ...prev, scanning: false, scanning_nodes: [] } : prev
        );
        void refreshDashboard();
      });

      es.onerror = () => {
        if (activeScanEventSourceRef.current !== es) return;
        es.close();
        activeScanEventSourceRef.current = null;
        if (epoch !== authEpochRef.current) return;
        failedStreamTaskIdsRef.current.add(String(taskId));
        setPollFallback(true);
      };
    },
    [authEpochRef, closeScanStream, queryClient, refreshDashboard]
  );

  useEffect(() => {
    if (!authenticated || !dashboardData) return;
    if (dashboardData.scanning) {
      setScanningNodes(Array.isArray(dashboardData.scanning_nodes) ? dashboardData.scanning_nodes : []);
      setIsScanActive(true);
      const activeId = dashboardData.active_scan_task_id;
      if (!activeScanEventSourceRef.current) {
        if (activeId && isStreamableScanTaskId(activeId, failedStreamTaskIdsRef.current)) {
          attachScanStream(activeId);
        } else {
          setScanProgressText((prev) => prev || 'Scanning in progress...');
          setPollFallback(true);
        }
      }
    } else if (!activeScanEventSourceRef.current) {
      setPollFallback(false);
      setScanningNodes([]);
      setIsScanActive(false);
      setScanProgressText('');
    }
  }, [authenticated, dashboardData, attachScanStream]);

  const triggerScan = useCallback(
    async (targetNode = '') => {
      const epoch = authEpochRef.current;
      setPollFallback(false);
      setIsScanActive(true);
      setScanningNodes(targetNode ? [targetNode] : approvedNodes.map((n) => n.name));
      setScanProgressText(
        targetNode ? `Initializing scan for [${targetNode}]...` : 'Initializing full security scan...'
      );

      try {
        const res = await apiClient.post<ScanTriggerResp>(
          '/api/scan',
          targetNode ? { node: targetNode } : undefined,
          { validateStatus: (s) => (s >= 200 && s < 300) || s === 409 }
        );
        if (epoch !== authEpochRef.current) return;

        const data = res.data || {};
        if (Array.isArray(data.scanning_nodes) && (res.status === 409 || data.scanning_nodes.length > 0)) {
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
    [approvedNodes, attachScanStream, authEpochRef, onUnauthorized, refreshDashboard]
  );

  return {
    scanningNodes,
    scanProgressText,
    pollFallback,
    effectiveScanActive: isScanActive || Boolean(dashboardData?.scanning) || scanningNodes.length > 0,
    triggerScan,
    resetScanState,
  };
}
