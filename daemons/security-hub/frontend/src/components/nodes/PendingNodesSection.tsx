import type React from 'react';
import type { NodeInfo } from '../../types';

interface PendingNodesSectionProps {
  pendingNodes: NodeInfo[];
  onApproveNode: (name: string) => void;
  onRejectNode: (name: string) => void;
}

/**
 * Displays incoming LAN agent announcements awaiting administrator approval or dismissal.
 */
export const PendingNodesSection: React.FC<PendingNodesSectionProps> = ({
  pendingNodes,
  onApproveNode,
  onRejectNode,
}) => {
  if (pendingNodes.length === 0) return null;

  return (
    <div id="pending-nodes-section" className="mb-3.5">
      <div className="font-bold text-xs text-amber-500 uppercase mb-1.5 flex items-center gap-1.5">
        <span>⚠️ Pending Agent Registrations</span>
        <span className="badge warn text-[11px] px-1.5 py-0.25" id="modal-pending-count">
          {pendingNodes.length}
        </span>
      </div>

      <div
        id="pending-nodes-list"
        className="bg-slate-900 p-3 rounded-lg border border-slate-700 text-[13px] flex flex-col gap-2.5"
      >
        {pendingNodes.map((n) => (
          <div
            key={n.name}
            className="flex justify-between items-center py-2 border-b border-slate-700 last:border-b-0"
          >
            <div>
              <div className="flex items-center gap-1.5">
                <span className="dot amber" />
                <strong>{n.name}</strong>
                <span className="badge warn text-[10px] px-1.5 py-0.25">PENDING</span>
                {n.os_version && (
                  <span className="badge skip text-[10px] px-1.5 py-0.25">{n.os_version}</span>
                )}
              </div>
              <div className="text-xs text-slate-400 font-mono break-all mt-0.5">
                {n.url || 'LAN Node'}
              </div>
            </div>
            <div className="flex gap-1.5">
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => onApproveNode(n.name)}
              >
                Approve
              </button>
              <button type="button" className="btn btn-danger" onClick={() => onRejectNode(n.name)}>
                Dismiss
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
