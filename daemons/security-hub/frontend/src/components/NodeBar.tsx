import type React from 'react';
import { cn } from '../lib/cn';
import { isNodeScanningName } from '../lib/domain';
import type { NodeInfo } from '../types';
import { Button, type DotStatus, StatusDot } from './ui';

interface NodeBarProps {
  approvedNodes: NodeInfo[];
  scanningNodes: string[];
  currentNodeFilter: string;
  onSelectNodeFilter: (nodeName: string) => void;
  onOpenNodesModal: () => void;
}

function getNodeStatusDot(node: NodeInfo, scanning: boolean): DotStatus {
  if (scanning) return 'scanning';
  return node.online ? 'green' : 'amber';
}

function getNodeTooltip(node: NodeInfo, scanning: boolean): string {
  if (scanning) return 'Scanning in progress...';
  if (node.last_error) return `Offline: ${node.last_error}`;
  return node.url || 'Local Host';
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
    approvedNodes.every((node) => isNodeScanningName(scanningNodes, node.name));

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

        {approvedNodes.map((node) => {
          const scanning = isNodeScanningName(scanningNodes, node.name);
          const roleTag = node.role === 'hub' ? 'Hub' : 'Agent';

          return (
            <button
              type="button"
              key={node.name}
              className={cn(
                'node-pill',
                currentNodeFilter === node.name && 'active',
                scanning && 'scanning'
              )}
              title={getNodeTooltip(node, scanning)}
              onClick={() => onSelectNodeFilter(node.name)}
            >
              <StatusDot status={getNodeStatusDot(node, scanning)} />
              <span>{node.name}</span>
              <span className="text-[10px] uppercase px-1.5 py-0.25 rounded bg-slate-700 text-slate-300">
                {roleTag}
              </span>
              {scanning && <span className="node-scan-status">⟳ Scanning</span>}
            </button>
          );
        })}
      </div>

      <Button variant="ghost" onClick={onOpenNodesModal}>
        ⚙ Manage Nodes
      </Button>
    </div>
  );
};
