import type React from 'react';
import type { NodeInfo } from '../../types';
import { Badge, Button, StatusDot } from '../ui';

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
        <Badge tone="warn" className="text-[11px] px-1.5 py-0.25" id="modal-pending-count">
          {pendingNodes.length}
        </Badge>
      </div>

      <div id="pending-nodes-list" className="inset-panel">
        {pendingNodes.map((node) => (
          <div
            key={node.name}
            className="flex justify-between items-center gap-4 py-2 border-b border-slate-700 last:border-b-0"
          >
            <div className="min-w-0 flex-1">
              <div className="flex items-center flex-wrap gap-1.5">
                <StatusDot status="amber" />
                <strong>{node.name}</strong>
                <Badge tone="warn" className="text-[11px] px-1.5 py-0.5 leading-none">
                  PENDING
                </Badge>
                {node.os_version && (
                  <Badge tone="skip" className="text-[11px] px-1.5 py-0.5 leading-none">
                    {node.os_version}
                  </Badge>
                )}
                {node.version && (
                  <span className="inline-flex items-center rounded-full px-2 py-0.5 text-[11px] font-mono font-semibold leading-none bg-sky-500/15 text-sky-300 border border-sky-500/35">
                    {node.version}
                  </span>
                )}
              </div>
              <div className="text-xs text-slate-400 font-mono break-all mt-1.5">
                {node.url || 'LAN Node'}
              </div>
            </div>
            <div className="flex gap-1.5 ml-4 shrink-0">
              <Button variant="primary" onClick={() => onApproveNode(node.name)}>
                Approve
              </Button>
              <Button variant="danger" onClick={() => onRejectNode(node.name)}>
                Dismiss
              </Button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
