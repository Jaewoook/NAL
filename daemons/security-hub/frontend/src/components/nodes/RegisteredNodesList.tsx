import type React from 'react';
import type { NodeInfo } from '../../types';
import { Badge, Button, StatusDot } from '../ui';

interface RegisteredNodesListProps {
  activeNodes: NodeInfo[];
  rejectedNodes: NodeInfo[];
  onApproveNode: (name: string) => void;
  onDeleteNode: (name: string) => void;
}

/**
 * Renders approved compute nodes alongside previously dismissed/rejected nodes.
 */
export const RegisteredNodesList: React.FC<RegisteredNodesListProps> = ({
  activeNodes,
  rejectedNodes,
  onApproveNode,
  onDeleteNode,
}) => {
  return (
    <>
      <div className="font-bold text-xs text-slate-400 uppercase mb-1.5">
        Registered Compute Nodes
      </div>

      <div id="nodes-modal-list" className="inset-panel mb-3.5">
        {activeNodes.map((node) => (
          <div
            key={node.name}
            className="flex justify-between items-center gap-4 py-1.5 border-b border-slate-700 last:border-b-0"
          >
            <div className="min-w-0 flex-1">
              <span className="inline-flex items-center flex-wrap gap-1.5">
                <StatusDot status={node.online ? 'green' : 'amber'} />
                <strong>{node.name}</strong>
                <Badge tone="skip" className="text-[11px] px-1.5 py-0.5 leading-none">
                  {node.role}
                </Badge>
                {node.os_version && (
                  <Badge tone="skip" className="text-[11px] px-1.5 py-0.5 leading-none">
                    {node.os_version}
                  </Badge>
                )}
              </span>
              <div className="text-xs text-slate-400 font-mono break-all mt-1.5">
                {node.url || 'Local Hub Host'} {node.last_error ? `· ${node.last_error}` : ''}
              </div>
            </div>
            {node.role !== 'hub' && (
              <Button
                variant="danger"
                className="ml-4 shrink-0"
                onClick={() => onDeleteNode(node.name)}
              >
                Remove
              </Button>
            )}
          </div>
        ))}

        {rejectedNodes.length > 0 && (
          <div className="mt-3.5 pt-2 border-t border-dashed border-slate-700">
            <div className="text-[11px] font-semibold text-slate-400 uppercase mb-1.5">
              Dismissed Nodes ({rejectedNodes.length})
            </div>
            {rejectedNodes.map((node) => (
              <div
                key={node.name}
                className="flex justify-between items-center gap-4 py-1.5 border-b border-slate-700 last:border-b-0 opacity-80"
              >
                <div className="min-w-0 flex-1">
                  <span className="inline-flex items-center flex-wrap gap-1.5">
                    <StatusDot status="red" />
                    <strong>{node.name}</strong>
                    <Badge tone="warn" className="text-[11px] px-1.5 py-0.5 leading-none">
                      REJECTED
                    </Badge>
                  </span>
                  <div className="text-xs text-slate-400 font-mono break-all mt-1.5">
                    {node.url || 'LAN Node'}
                  </div>
                </div>
                <div className="flex gap-1.5 ml-4 shrink-0">
                  <Button
                    variant="primary"
                    className="px-2 py-0.5 text-[11px]"
                    onClick={() => onApproveNode(node.name)}
                  >
                    Re-Approve
                  </Button>
                  <Button
                    variant="danger"
                    className="px-2 py-0.5 text-[11px]"
                    onClick={() => onDeleteNode(node.name)}
                  >
                    Remove
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
};
