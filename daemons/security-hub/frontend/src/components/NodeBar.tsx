import type React from 'react';
import { cn } from '../lib/cn';
import { isNodeScanningName } from '../lib/domain';
import type { NodeInfo } from '../types';

interface NodeBarProps {
  approvedNodes: NodeInfo[];
  scanningNodes: string[];
  currentNodeFilter: string;
  onSelectNodeFilter: (nodeName: string) => void;
  onOpenNodesModal: () => void;
}

/**
 * Horizontal filter strip displaying approved compute nodes and live scanning badges.
 */
export const NodeBar: React.FC<NodeBarProps> = ({
  approvedNodes,
  scanningNodes,
  currentNodeFilter,
  onSelectNodeFilter,
  onOpenNodesModal,
}) => {
  const isAllScanning =
    approvedNodes.length > 0 &&
    approvedNodes.every((n) => isNodeScanningName(scanningNodes, n.name));

  return (
    <div className="flex justify-between items-center mb-4 gap-3 flex-wrap">
      <div className="flex gap-2 flex-wrap" id="node-pills-container">
        <button
          type="button"
          className={cn(
            'node-pill',
            currentNodeFilter === 'all' && 'active',
            isAllScanning && 'scanning'
          )}
          onClick={() => onSelectNodeFilter('all')}
        >
          <span>All Nodes ({approvedNodes.length})</span>
          {isAllScanning && <span className="node-scan-status">⟳ Scanning</span>}
        </button>

        {approvedNodes.map((n) => {
          const scanning = isNodeScanningName(scanningNodes, n.name);
          const dot = scanning ? 'scanning' : n.online ? 'green' : 'amber';
          const roleTag = n.role === 'hub' ? 'Hub' : 'Agent';
          const title = scanning
            ? 'Scanning in progress...'
            : n.last_error
              ? `Offline: ${n.last_error}`
              : n.url || 'Local Host';

          return (
            <button
              type="button"
              key={n.name}
              className={cn(
                'node-pill',
                currentNodeFilter === n.name && 'active',
                scanning && 'scanning'
              )}
              title={title}
              onClick={() => onSelectNodeFilter(n.name)}
            >
              <span className={cn('dot', dot)} />
              <span>{n.name}</span>
              <span className="text-[10px] uppercase px-1.5 py-0.25 rounded bg-slate-700 text-slate-300">
                {roleTag}
              </span>
              {scanning && <span className="node-scan-status">⟳ Scanning</span>}
            </button>
          );
        })}
      </div>

      <button type="button" className="btn btn-ghost" onClick={onOpenNodesModal}>
        ⚙ Manage Nodes
      </button>
    </div>
  );
};
