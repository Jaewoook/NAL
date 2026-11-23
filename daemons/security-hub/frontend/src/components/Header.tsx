import { Menu, MenuButton, MenuItem, MenuItems } from '@headlessui/react';
import type React from 'react';

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
 * Top sticky navigation bar housing scan controls, pending node alert, and Headless UI user menu.
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
    <header className="bg-[#0b1120] border-b border-slate-700 px-8 py-4 flex flex-wrap justify-between items-center gap-3 sticky top-0 z-20">
      <div className="flex items-center gap-3 font-bold text-lg">
        <span className="bg-gradient-to-br from-sky-400 to-indigo-400 text-[#0b1120] px-2 py-1 rounded-md text-xs font-extrabold">
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

          <button type="button" className="btn btn-ghost" onClick={onOpenLogsTab}>
            ▸ Task Logs
          </button>

          {isScanning && (
            <div id="scan-progress-box" className="inline-flex items-center">
              <span
                id="scan-progress-pill"
                className="badge warn font-mono max-w-[280px] overflow-hidden text-ellipsis whitespace-nowrap"
              >
                ⟳ <span id="scan-progress-text">{scanProgressText || 'Scanning...'}</span>
              </span>
            </div>
          )}

          <button
            type="button"
            className="btn btn-secondary"
            id="btn-scan-node"
            disabled={isScanning}
            onClick={onOpenScanNodeModal}
          >
            ↻ Scan Single Node
          </button>

          <button
            type="button"
            className="btn btn-primary"
            id="btn-scan-now"
            disabled={isScanning}
            onClick={onTriggerFullScan}
          >
            {isScanning ? '⟳ Scanning...' : '↻ Scan Now'}
          </button>

          <Menu as="div" className="relative inline-block" id="user-dropdown">
            <MenuButton
              id="user-chip-btn"
              className="inline-flex items-center gap-2 bg-slate-800 border border-slate-700 px-3.5 py-1.5 rounded-full text-slate-50 text-[13px] font-semibold cursor-pointer transition-all hover:bg-[#263449] hover:border-sky-400"
            >
              <span id="auth-username">{username}</span>
              <span className="text-[10px] text-slate-400">▾</span>
            </MenuButton>

            <MenuItems
              id="user-menu"
              className="absolute top-[calc(100%+8px)] right-0 bg-[#0b1120] border border-slate-700 rounded-[10px] min-w-[210px] py-1.5 shadow-[0_10px_25px_-5px_rgba(0,0,0,0.65),0_8px_10px_-6px_rgba(0,0,0,0.5)] z-50 flex flex-col focus:outline-none"
            >
              <div className="px-4 pt-2 pb-2.5 border-b border-slate-700 text-xs text-slate-400">
                <span className="block text-[11px] uppercase tracking-wider text-slate-500 mb-0.5">
                  Signed in as
                </span>
                <strong id="auth-user-detail" className="text-slate-100">
                  {username} ({(authMethod || 'sso').toUpperCase()})
                </strong>
              </div>
              <MenuItem>
                <a
                  className="flex items-center gap-2.5 px-4 py-2.25 text-slate-50 no-underline text-[13px] font-medium data-[focus]:bg-[#263449] data-[focus]:text-white"
                  href="https://auth.jaewook.dev/if/user/#/library"
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  <span className="text-[13px] w-4 inline-flex justify-center">⊞</span>
                  <span>Dashboard</span>
                  <span className="ml-auto text-[11px] text-slate-400">↗</span>
                </a>
              </MenuItem>
              <MenuItem>
                <button
                  type="button"
                  className="flex items-center gap-2.5 px-4 py-2.25 text-slate-50 text-[13px] font-medium bg-transparent border-0 w-full text-left cursor-pointer data-[focus]:bg-[#263449] data-[focus]:text-white"
                  onClick={onRegisterPasskey}
                >
                  <span className="text-[13px] w-4 inline-flex justify-center">🔑</span>
                  <span>Register Passkey</span>
                </button>
              </MenuItem>
              <div className="h-px bg-slate-700 my-1.5" />
              <MenuItem>
                <button
                  type="button"
                  className="flex items-center gap-2.5 px-4 py-2.25 text-red-400 text-[13px] font-medium bg-transparent border-0 w-full text-left cursor-pointer data-[focus]:bg-red-500/15 data-[focus]:text-red-300"
                  onClick={onLogout}
                >
                  <span className="text-[13px] w-4 inline-flex justify-center">⎋</span>
                  <span>Sign out</span>
                </button>
              </MenuItem>
            </MenuItems>
          </Menu>
        </div>
      )}
    </header>
  );
};
