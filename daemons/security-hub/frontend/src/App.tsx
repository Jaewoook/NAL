import type React from 'react';
import { useCallback, useRef, useState } from 'react';
import { BrokenLinkageModal } from './components/BrokenLinkageModal';
import { ConfirmModal } from './components/ConfirmModal';
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
import { useConfirmDialog } from './hooks/useConfirmDialog';
import { useDashboardData } from './hooks/useDashboardData';
import { useItemActions } from './hooks/useItemActions';
import { useNodeActions } from './hooks/useNodeActions';
import { useScanStream } from './hooks/useScanStream';
import { useTaskLogStream } from './hooks/useTaskLogStream';
import type { PendingUpdateRequest, TabType } from './types';

/**
 * Root presentation shell composing auth, dashboard data, SSE streams, and action modals.
 */
export const App: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<TabType>('docker');
  const [pollFallback, setPollFallback] = useState(false);
  const [selectedVersions, setSelectedVersions] = useState<Record<string, string>>({});
  const [pendingUpdateReq, setPendingUpdateReq] = useState<PendingUpdateRequest | null>(null);
  const [nodesModalOpen, setNodesModalOpen] = useState(false);
  const [scanNodeModalOpen, setScanNodeModalOpen] = useState(false);
  const [linkageModal, setLinkageModal] = useState<{ pkgName: string; details: string } | null>(
    null
  );

  const confirm = useConfirmDialog();
  const streamResettersRef = useRef<{ scan?: () => void; task?: () => void }>({});

  const resetUIState = useCallback(() => {
    streamResettersRef.current.scan?.();
    streamResettersRef.current.task?.();
    confirm.cancelConfirm();
    setSelectedVersions({});
    setPendingUpdateReq(null);
    setNodesModalOpen(false);
    setScanNodeModalOpen(false);
    setLinkageModal(null);
  }, [confirm.cancelConfirm]);

  const auth = useAuth({ onSessionReset: resetUIState });

  const dashboard = useDashboardData({
    authenticated: auth.authenticated,
    pollFallback,
    currentTab,
    onUnauthorized: auth.handleUnauthorized,
  });

  const scanStream = useScanStream({
    authenticated: auth.authenticated,
    dashboardData: dashboard.dashboardData,
    approvedNodes: dashboard.approvedNodes,
    authEpochRef: auth.authEpochRef,
    onPollFallbackChange: setPollFallback,
    onUnauthorized: auth.handleUnauthorized,
    refreshDashboard: dashboard.refreshDashboard,
  });

  const taskLogStream = useTaskLogStream({
    authEpochRef: auth.authEpochRef,
    refreshDashboard: dashboard.refreshDashboard,
  });

  streamResettersRef.current.scan = scanStream.resetScanState;
  streamResettersRef.current.task = taskLogStream.resetTaskLogs;

  const handleOpenTaskLog = useCallback(
    (taskId: string) => {
      setCurrentTab('logs');
      if (taskId) taskLogStream.streamTaskLogs(taskId);
    },
    [taskLogStream.streamTaskLogs]
  );

  const itemActions = useItemActions({
    hubNode: dashboard.hubNode,
    authEpochRef: auth.authEpochRef,
    onUnauthorized: auth.handleUnauthorized,
    refreshDashboard: dashboard.refreshDashboard,
    onOpenTaskLog: handleOpenTaskLog,
    requestConfirm: confirm.requestConfirm,
  });

  const nodeActions = useNodeActions({
    currentNodeFilter: dashboard.currentNodeFilter,
    authEpochRef: auth.authEpochRef,
    onUnauthorized: auth.handleUnauthorized,
    refreshDashboard: dashboard.refreshDashboard,
    onResetNodeFilter: () => dashboard.setCurrentNodeFilter('all'),
    requestConfirm: confirm.requestConfirm,
  });

  return (
    <>
      <Header
        authenticated={auth.authenticated}
        username={auth.username}
        authMethod={auth.authMethod}
        pendingNodesCount={dashboard.pendingNodesCount}
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
              items={dashboard.nodeFilteredItems}
              tasksCount={dashboard.tabCounts.logs}
              scannedAt={dashboard.dashboardData?.scan?.scanned_at}
            />

            <NodeBar
              approvedNodes={dashboard.approvedNodes}
              scanningNodes={scanStream.scanningNodes}
              currentNodeFilter={dashboard.currentNodeFilter}
              onSelectNodeFilter={dashboard.setCurrentNodeFilter}
              onOpenNodesModal={() => setNodesModalOpen(true)}
            />

            <DashboardTabs
              currentTab={currentTab}
              counts={dashboard.tabCounts}
              onSelectTab={setCurrentTab}
            />

            {currentTab === 'logs' ? (
              <TaskLogsPanel
                tasks={dashboard.dashboardData?.recent_tasks || []}
                activeTaskId={taskLogStream.activeTaskId}
                logs={taskLogStream.taskLogLines}
                onSelectTask={taskLogStream.streamTaskLogs}
              />
            ) : (
              <ItemsTable
                items={dashboard.sortedTabItems}
                hubNode={dashboard.hubNode}
                selectedVersions={selectedVersions}
                onSelectVersion={(itemKey, version) =>
                  setSelectedVersions((prev) => ({ ...prev, [itemKey]: version }))
                }
                onOpenBrokenLinkage={(pkgName, details) => setLinkageModal({ pkgName, details })}
                onOpenUpdateModal={(item, targetVersion) =>
                  setPendingUpdateReq({
                    node: item.node || dashboard.hubNode || 'local',
                    target_type: item.target_type,
                    target_name: item.name,
                    current_version: item.current_version,
                    target_version: targetVersion,
                    broken_linkage: Boolean(item.broken_linkage),
                    stateful: Boolean(item.stateful),
                  })
                }
                onSkipItem={itemActions.skipItem}
                onUnskipItem={itemActions.unskipItem}
                onRollbackService={(nodeName, svcName) =>
                  void itemActions.rollbackService(nodeName, svcName)
                }
              />
            )}
          </div>
        )}

        <UpdateModal
          request={pendingUpdateReq}
          onConfirm={(req, runBackup, enableDeadMan) => {
            setPendingUpdateReq(null);
            void itemActions.confirmUpdate(req, runBackup, enableDeadMan);
          }}
          onClose={() => setPendingUpdateReq(null)}
        />

        <NodesModal
          open={nodesModalOpen}
          nodes={dashboard.allNodes}
          onApproveNode={nodeActions.approveNode}
          onRejectNode={(name) => void nodeActions.rejectNode(name)}
          onDeleteNode={(name) => void nodeActions.deleteNode(name)}
          onSaveNode={nodeActions.saveNode}
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
          approvedNodes={dashboard.approvedNodes}
          scanningNodes={scanStream.scanningNodes}
          currentNodeFilter={dashboard.currentNodeFilter}
          isScanActive={scanStream.effectiveScanActive}
          onStartNodeScan={(targetNode) => void scanStream.triggerScan(targetNode)}
          onClose={() => setScanNodeModalOpen(false)}
        />

        <ConfirmModal
          state={confirm.confirmDialog}
          onConfirm={confirm.acceptConfirm}
          onCancel={confirm.cancelConfirm}
        />
      </div>
    </>
  );
};

export default App;
