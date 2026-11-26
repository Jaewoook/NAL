import type React from 'react';
import { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { isNodeScanningName } from '../lib/domain';
import type { NodeInfo } from '../types';
import { Modal } from './Modal';
import { Badge, Button, type DotStatus, StatusDot } from './ui';

interface ScanNodeModalProps {
  open: boolean;
  approvedNodes: NodeInfo[];
  scanningNodes: string[];
  currentNodeFilter: string;
  isScanActive: boolean;
  onStartNodeScan: (targetNode: string) => void;
  onClose: () => void;
}

/**
 * Modal dialog allowing selection of a single approved compute node to scan.
 */
export const ScanNodeModal: React.FC<ScanNodeModalProps> = ({
  open,
  approvedNodes,
  scanningNodes,
  currentNodeFilter,
  isScanActive,
  onStartNodeScan,
  onClose,
}) => {
  const [selectedNode, setSelectedNode] = useState('');

  useEffect(() => {
    if (!open || approvedNodes.length === 0) {
      setSelectedNode('');
      return;
    }

    setSelectedNode((prev) => {
      if (prev) {
        const prevMatch = approvedNodes.find((n) => n.name.toLowerCase() === prev.toLowerCase());
        if (prevMatch) return prevMatch.name;
      }
      if (currentNodeFilter && currentNodeFilter !== 'all') {
        const filterMatch = approvedNodes.find(
          (n) => n.name.toLowerCase() === currentNodeFilter.toLowerCase()
        );
        if (filterMatch) return filterMatch.name;
      }
      return approvedNodes[0].name;
    });
  }, [open, approvedNodes, currentNodeFilter]);

  const confirmDisabled = isScanActive || approvedNodes.length === 0 || !selectedNode;

  const handleConfirm = () => {
    if (!selectedNode) {
      toast.error('Please select a node to scan.');
      return;
    }
    const target = selectedNode;
    onClose();
    onStartNodeScan(target);
  };

  return (
    <Modal
      id="modal-scan-node"
      open={open}
      onClose={onClose}
      titleId="modal-scan-node-title"
      title="Scan Single Node"
    >
      <p className="text-slate-400 text-[13px] mt-2 mb-3.5">
        Select a registered compute node to execute a targeted security scan:
      </p>

      <div id="scan-node-modal-list" className="inset-panel max-h-[320px] overflow-y-auto mb-4">
        {approvedNodes.length === 0 ? (
          <div className="text-slate-400 text-[13px] p-3 text-center">
            No approved nodes available to scan.
          </div>
        ) : (
          approvedNodes.map((node, idx) => {
            const dot: DotStatus = node.online ? 'green' : 'amber';
            const scanning = isNodeScanningName(scanningNodes, node.name);
            const inputId = `scan-node-radio-${idx}`;

            return (
              <label key={node.name} className="scan-node-option" htmlFor={inputId}>
                <input
                  type="radio"
                  id={inputId}
                  name="scan-target-node"
                  value={node.name}
                  className="shrink-0"
                  checked={selectedNode === node.name}
                  onChange={() => setSelectedNode(node.name)}
                />
                <div className="min-w-0 flex-1">
                  <span className="inline-flex items-center flex-wrap gap-1.5">
                    <StatusDot status={scanning ? 'scanning' : dot} />
                    <strong>{node.name}</strong>
                    <Badge tone="skip" className="text-[11px] px-1.5 py-0.5 leading-none">
                      {node.role}
                    </Badge>
                    {node.os_version && (
                      <Badge tone="skip" className="text-[11px] px-1.5 py-0.5 leading-none">
                        {node.os_version}
                      </Badge>
                    )}
                    {scanning && <span className="node-scan-status">⟳ Scanning</span>}
                  </span>
                  <div className="text-xs text-slate-400 font-mono break-all mt-1.5">
                    {node.url || 'Local Hub Host'}
                  </div>
                </div>
              </label>
            );
          })
        )}
      </div>

      <div className="flex gap-2.5 justify-end">
        <Button
          id="btn-confirm-scan-node"
          variant="primary"
          disabled={confirmDisabled}
          onClick={handleConfirm}
        >
          ↻ Start Scan
        </Button>
        <Button variant="ghost" onClick={onClose}>
          Cancel
        </Button>
      </div>
    </Modal>
  );
};
