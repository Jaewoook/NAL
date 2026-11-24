import type React from 'react';
import { UserMenuDropdown } from './UserMenuDropdown';
import { Badge, Button } from './ui';

interface HeaderProps {
  authenticated: boolean;
  username: string;
  authMethod: string;
  pendingNodesCount: number;
  isScanning: boolean;
  scanProgressText: string;
  onOpenNodesModal: () => void;
  onOpenLogsTab: () => void;
  onOpenScanNodeModal: () => void;
  onTriggerFullScan: () => void;
  onRegisterPasskey: () => void;
  onLogout: () => void;
}

/**
 * Top sticky navigation bar housing scan controls, pending node alert, and user account menu.
 */
export const Header: React.FC<HeaderProps> = ({
  authenticated,
  username,
  authMethod,
  pendingNodesCount,
  isScanning,
  scanProgressText,
  onOpenNodesModal,
  onOpenLogsTab,
  onOpenScanNodeModal,
  onTriggerFullScan,
  onRegisterPasskey,
  onLogout,
}) => {
  return (
    <header className="bg-surface-header border-b border-slate-700 px-8 py-4 flex flex-wrap justify-between items-center gap-3 sticky top-0 z-20">
      <div className="flex items-center gap-3 font-bold text-lg">
        <span className="bg-gradient-to-br from-sky-400 to-indigo-400 text-surface-header px-2 py-1 rounded-md text-xs font-extrabold">
          NAL
        </span>
        <span>Security Hub</span>
      </div>

      {authenticated && (
        <div className="flex flex-wrap items-center gap-2.5 text-[13px]" id="header-actions">
          {pendingNodesCount > 0 && (
            <div id="pending-nodes-container" className="inline-flex">
              <button
                type="button"
                id="pending-nodes-banner"
                className="btn badge warn cursor-pointer inline-flex items-center gap-1.5"
                onClick={onOpenNodesModal}
              >
                ⚠️ <span id="pending-nodes-count">{pendingNodesCount}</span> Pending Node(s)
              </button>
            </div>
          )}

          <Button variant="ghost" onClick={onOpenLogsTab}>
            ▸ Task Logs
          </Button>

          {isScanning && (
            <div id="scan-progress-box" className="inline-flex items-center">
              <Badge
                id="scan-progress-pill"
                tone="warn"
                className="font-mono max-w-[280px] overflow-hidden text-ellipsis whitespace-nowrap"
              >
                ⟳ <span id="scan-progress-text">{scanProgressText || 'Scanning...'}</span>
              </Badge>
            </div>
          )}

          <Button
            variant="secondary"
            id="btn-scan-node"
            disabled={isScanning}
            onClick={onOpenScanNodeModal}
          >
            ↻ Scan Single Node
          </Button>

          <Button
            variant="primary"
            id="btn-scan-now"
            disabled={isScanning}
            onClick={onTriggerFullScan}
          >
            {isScanning ? '⟳ Scanning...' : '↻ Scan Now'}
          </Button>

          <UserMenuDropdown
            username={username}
            authMethod={authMethod}
            onRegisterPasskey={onRegisterPasskey}
            onLogout={onLogout}
          />
        </div>
      )}
    </header>
  );
};
