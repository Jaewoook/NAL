import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { apiClient, getItemSortRank, isAxiosUnauthorized } from './api';
import { BrokenLinkageModal } from './components/BrokenLinkageModal';
import { DashboardTabs } from './components/DashboardTabs';
import { Header } from './components/Header';
import { ItemsTable } from './components/ItemsTable';
import { LoginView } from './components/LoginView';
import { NodeBar } from './components/NodeBar';
import { NodesModal } from './components/NodesModal';
import { ScanNodeModal } from './components/ScanNodeModal';
import { SummaryGrid } from './components/SummaryGrid';
import { TaskLogsPanel } from './components/TaskLogsPanel';
import { UpdateModal } from './components/UpdateModal';
import { useAuth } from './hooks/useAuth';
import { useDashboardActions } from './hooks/useDashboardActions';
import { useScanStream } from './hooks/useScanStream';
import { useTaskLogStream } from './hooks/useTaskLogStream';
import type { DashboardResponse, NodeInfo, PendingUpdateRequest, TabType } from './types';

/**
 * Root presentation shell composing auth, dashboard queries, scan/log streams, and modals.
 */
export const App: React.FC = () => {
  const queryClient = useQueryClient();

  const [currentTab, setCurrentTab] = useState<TabType>('docker');
  const [currentNodeFilter, setCurrentNodeFilter] = useState<string>('all');
  const [selectedVersions, setSelectedVersions] = useState<Record<string, string>>({});
  const [pendingUpdateReq, setPendingUpdateReq] = useState<PendingUpdateRequest | null>(null);
  const [nodesModalOpen, setNodesModalOpen] = useState(false);
  const [scanNodeModalOpen, setScanNodeModalOpen] = useState(false);
  const [linkageModal, setLinkageModal] = useState<{ pkgName: string; details: string } | null>(null);

  const resetStreamsRef = useRef<() => void>(() => undefined);

  const resetUIState = useCallback(() => {
    resetStreamsRef.current();
    setSelectedVersions({});
    setPendingUpdateReq(null);
    setNodesModalOpen(false);
    setScanNodeModalOpen(false);
    setLinkageModal(null);
  }, []);

  const auth = useAuth({ onSessionReset: resetUIState });

  const refreshDashboard = useCallback(
    () => queryClient.invalidateQueries({ queryKey: ['dashboard'] }),
    [queryClient]
  );

  const [pollFallback, setPollFallback] = useState(false);

  const dashboardQuery = useQuery({
    queryKey: ['dashboard'],
    enabled: auth.authenticated,
    refetchInterval: pollFallback ? 2000 : false,
    queryFn: async () => {
      try {
        const { data } = await apiClient.get<DashboardResponse>('/api/dashboard');
        return data;
      } catch (err) {
        if (isAxiosUnauthorized(err)) {
          auth.handleUnauthorized();
        }
        throw err;
      }
    },
  });

  const dashboardData = dashboardQuery.data ?? null;
  const hubNode = dashboardData?.hub_node || 'local';

  const allNodes: NodeInfo[] = useMemo(() => {
    if (dashboardData?.nodes) return dashboardData.nodes;
    return [{ name: hubNode, role: 'hub', status: 'approved', online: true }];
  }, [dashboardData, hubNode]);

  const approvedNodes = useMemo(
    () => allNodes.filter((n) => !n.status || n.status === 'approved'),
    [allNodes]
  );

  useEffect(() => {
    if (!dashboardData || currentNodeFilter === 'all') return;
    const stillApproved = approvedNodes.some(
      (n) => n.name.toLowerCase() === currentNodeFilter.toLowerCase()
    );
    if (!stillApproved) setCurrentNodeFilter('all');
  }, [dashboardData, approvedNodes, currentNodeFilter]);

  const scanStream = useScanStream({
    authenticated: auth.authenticated,
    dashboardData,
    approvedNodes,
    authEpochRef: auth.authEpochRef,
    onUnauthorized: auth.handleUnauthorized,
    refreshDashboard,
  });

  useEffect(() => {
    setPollFallback(scanStream.pollFallback);
  }, [scanStream.pollFallback]);

  const taskLogStream = useTaskLogStream({
    authEpochRef: auth.authEpochRef,
    refreshDashboard,
  });

  useEffect(() => {
    resetStreamsRef.current = () => {
      scanStream.resetScanState();
      taskLogStream.resetTaskLogs();
    };
  }, [scanStream.resetScanState, taskLogStream.resetTaskLogs]);

  const handleOpenTaskLog = useCallback(
    (taskId: string) => {
      setCurrentTab('logs');
      if (taskId) taskLogStream.streamTaskLogs(taskId);
    },
    [taskLogStream.streamTaskLogs]
  );

  const actions = useDashboardActions({
    hubNode,
    currentNodeFilter,
    authEpochRef: auth.authEpochRef,
    onUnauthorized: auth.handleUnauthorized,
    refreshDashboard,
    onOpenTaskLog: handleOpenTaskLog,
    onResetNodeFilter: () => setCurrentNodeFilter('all'),
  });

  const pendingNodesCount = useMemo(
    () => allNodes.filter((n) => n.status === 'pending').length,
    [allNodes]
  );

  const nodeFilteredItems = useMemo(() => {
    const allItems = dashboardData?.scan?.items || [];
    if (currentNodeFilter === 'all') return allItems;
    return allItems.filter((item) => (item.node || hubNode) === currentNodeFilter);
  }, [dashboardData, currentNodeFilter, hubNode]);

  const tabCounts = useMemo(
    () => ({
      docker: nodeFilteredItems.filter((i) => i.target_type === 'docker').length,
      brew: nodeFilteredItems.filter((i) => i.target_type === 'brew' || i.target_type === 'apt').length,
      daemons: nodeFilteredItems.filter((i) => i.target_type === 'daemon' || i.target_type === 'macos').length,
      logs: (dashboardData?.recent_tasks || []).length,
    }),
    [nodeFilteredItems, dashboardData]
  );

  const sortedTabItems = useMemo(() => {
    const filtered = nodeFilteredItems.filter((item) => {
      if (currentTab === 'docker') return item.target_type === 'docker';
      if (currentTab === 'brew') return item.target_type === 'brew' || item.target_type === 'apt';
      return item.target_type === 'daemon' || item.target_type === 'macos';
    });
    return [...filtered].sort((a, b) => {
      const rankDiff = getItemSortRank(a) - getItemSortRank(b);
      return rankDiff !== 0
        ? rankDiff
        : (a.name || '').localeCompare(b.name || '', undefined, { sensitivity: 'base' });
    });
  }, [nodeFilteredItems, currentTab]);

  return (
    <>
      <Header
        authenticated={auth.authenticated}
        username={auth.username}
        authMethod={auth.authMethod}
        pendingNodesCount={pendingNodesCount}
        isScanning={scanStream.effectiveScanActive}
        scanProgressText={scanStream.scanProgressText}
        onOpenNodesModal={() => setNodesModalOpen(true)}
        onOpenLogsTab={() => setCurrentTab('logs')}
        onOpenScanNodeModal={() => setScanNodeModalOpen(true)}
        onTriggerFullScan={() => void scanStream.triggerScan('')}
        onRegisterPasskey={() => void auth.registerPasskey()}
        onLogout={() => void auth.logout()}
      />

      <div className="max-w-[1320px] mx-auto my-6 px-6">
        {auth.sessionChecked && !auth.authenticated && (
          <LoginView onPasskeyLogin={() => void auth.loginWithPasskey()} />
        )}

        {auth.authenticated && (
          <div id="view-dashboard">
            <SummaryGrid
              items={nodeFilteredItems}
              tasksCount={tabCounts.logs}
              scannedAt={dashboardData?.scan?.scanned_at}
            />

            <NodeBar
              approvedNodes={approvedNodes}
              scanningNodes={scanStream.scanningNodes}
              currentNodeFilter={currentNodeFilter}
              onSelectNodeFilter={setCurrentNodeFilter}
              onOpenNodesModal={() => setNodesModalOpen(true)}
            />

            <DashboardTabs currentTab={currentTab} counts={tabCounts} onSelectTab={setCurrentTab} />

            {currentTab === 'logs' ? (
              <TaskLogsPanel
                tasks={dashboardData?.recent_tasks || []}
                activeTaskId={taskLogStream.activeTaskId}
                logs={taskLogStream.taskLogLines}
                onSelectTask={taskLogStream.streamTaskLogs}
              />
            ) : (
              <ItemsTable
                items={sortedTabItems}
                hubNode={hubNode}
                selectedVersions={selectedVersions}
                onSelectVersion={(itemKey, version) =>
                  setSelectedVersions((prev) => ({ ...prev, [itemKey]: version }))
                }
                onOpenBrokenLinkage={(pkgName, details) => setLinkageModal({ pkgName, details })}
                onOpenUpdateModal={(item, targetVersion) =>
                  setPendingUpdateReq({
                    node: item.node || hubNode || 'local',
                    target_type: item.target_type,
                    target_name: item.name,
                    current_version: item.current_version,
                    target_version: targetVersion,
                    broken_linkage: Boolean(item.broken_linkage),
                    stateful: Boolean(item.stateful),
                  })
                }
                onSkipItem={actions.skipItem}
                onUnskipItem={actions.unskipItem}
                onRollbackService={(nodeName, svcName) => void actions.rollbackService(nodeName, svcName)}
              />
            )}
          </div>
        )}

        <UpdateModal
          request={pendingUpdateReq}
          onConfirm={(req, runBackup, enableDeadMan) => {
            setPendingUpdateReq(null);
            void actions.confirmUpdate(req, runBackup, enableDeadMan);
          }}
          onClose={() => setPendingUpdateReq(null)}
        />

        <NodesModal
          open={nodesModalOpen}
          nodes={allNodes}
          onApproveNode={actions.approveNode}
          onRejectNode={actions.rejectNode}
          onDeleteNode={actions.deleteNode}
          onSaveNode={actions.saveNode}
          onUnauthorized={auth.handleUnauthorized}
          onClose={() => setNodesModalOpen(false)}
        />

        <BrokenLinkageModal
          open={Boolean(linkageModal)}
          pkgName={linkageModal?.pkgName || 'Package'}
          details={linkageModal?.details || ''}
          onClose={() => setLinkageModal(null)}
        />

        <ScanNodeModal
          open={scanNodeModalOpen}
          approvedNodes={approvedNodes}
          scanningNodes={scanStream.scanningNodes}
          currentNodeFilter={currentNodeFilter}
          isScanActive={scanStream.effectiveScanActive}
          onStartNodeScan={(targetNode) => void scanStream.triggerScan(targetNode)}
          onClose={() => setScanNodeModalOpen(false)}
        />
      </div>
    </>
  );
};

export default App;
