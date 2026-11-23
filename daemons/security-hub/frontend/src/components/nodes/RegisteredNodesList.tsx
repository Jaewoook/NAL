import type React from 'react';
import { cn } from '../../lib/cn';
import type { NodeInfo } from '../../types';

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

      <div
        id="nodes-modal-list"
        className="bg-slate-900 p-3 rounded-lg border border-slate-700 text-[13px] flex flex-col gap-2.5 mb-3.5"
      >
        {activeNodes.map((n) => (
          <div
            key={n.name}
            className="flex justify-between items-center py-1.5 border-b border-slate-700 last:border-b-0"
          >
            <div>
              <span className={cn('dot', n.online ? 'green' : 'amber')} /> <strong>{n.name}</strong>
              <span className="badge skip ml-1.5">{n.role}</span>
              {n.os_version && <span className="badge skip ml-1 text-[10px]">{n.os_version}</span>}
              <div className="text-xs text-slate-400 font-mono break-all">
                {n.url || 'Local Hub Host'} {n.last_error ? `· ${n.last_error}` : ''}
              </div>
            </div>
            {n.role !== 'hub' && (
              <button type="button" className="btn btn-danger" onClick={() => onDeleteNode(n.name)}>
                Remove
              </button>
            )}
          </div>
        ))}

        {rejectedNodes.length > 0 && (
          <div className="mt-3.5 pt-2 border-t border-dashed border-slate-700">
            <div className="text-[11px] font-semibold text-slate-400 uppercase mb-1.5">
              Dismissed Nodes ({rejectedNodes.length})
            </div>
            {rejectedNodes.map((n) => (
              <div
                key={n.name}
                className="flex justify-between items-center py-1.5 border-b border-slate-700 last:border-b-0 opacity-80"
              >
                <div>
                  <span className="dot red" /> <strong>{n.name}</strong>
                  <span className="badge warn ml-1.5 text-[10px] px-1.25 py-0.25">REJECTED</span>
                  <div className="text-xs text-slate-400 font-mono break-all">
                    {n.url || 'LAN Node'}
                  </div>
                </div>
                <div className="flex gap-1.5">
                  <button
                    type="button"
                    className="btn btn-primary px-2 py-0.5 text-[11px]"
                    onClick={() => onApproveNode(n.name)}
                  >
                    Re-Approve
                  </button>
                  <button
                    type="button"
                    className="btn btn-danger px-2 py-0.5 text-[11px]"
                    onClick={() => onDeleteNode(n.name)}
                  >
                    Remove
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </>
  );
};
