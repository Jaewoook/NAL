import React, { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { cn, isNodeScanningName } from '../api';
import type { NodeInfo } from '../types';
import { Modal } from './Modal';

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

      <div
        id="scan-node-modal-list"
        className="bg-slate-900 p-3 rounded-lg border border-slate-700 text-[13px] flex flex-col gap-2.5 max-h-[320px] overflow-y-auto mb-4"
      >
        {approvedNodes.length === 0 ? (
          <div className="text-slate-400 text-[13px] p-3 text-center">
            No approved nodes available to scan.
          </div>
        ) : (
          approvedNodes.map((n, idx) => {
            const dot = n.online ? 'green' : 'amber';
            const roleTag = n.role === 'hub' ? 'Hub' : 'Agent';
            const scanning = isNodeScanningName(scanningNodes, n.name);
            const inputId = `scan-node-radio-${idx}`;

            return (
              <label key={n.name} className="scan-node-option" htmlFor={inputId}>
                <div className="flex items-center gap-2.5 cursor-pointer flex-1">
                  <input
                    type="radio"
                    id={inputId}
                    name="scan-target-node"
                    value={n.name}
                    checked={selectedNode === n.name}
                    onChange={() => setSelectedNode(n.name)}
                  />
                  <span className={cn('dot', scanning ? 'scanning' : dot)} />
                  <strong>{n.name}</strong>
                  <span className="text-[10px] uppercase px-1.5 py-0.25 rounded bg-slate-700 text-slate-300">
                    {roleTag}
                  </span>
                  {n.os_version && (
                    <span className="badge skip text-[10px] px-1.5 py-0.25">{n.os_version}</span>
                  )}
                  {scanning && <span className="node-scan-status">⟳ Scanning</span>}
                </div>
                <div className="text-xs text-slate-400 font-mono break-all">
                  {n.url || 'Local Hub Host'}
                </div>
              </label>
            );
          })
        )}
      </div>

      <div className="flex gap-2.5 justify-end">
        <button
          type="button"
          id="btn-confirm-scan-node"
          className="btn btn-primary"
          disabled={confirmDisabled}
          onClick={handleConfirm}
        >
          ↻ Start Scan
        </button>
        <button type="button" className="btn btn-ghost" onClick={onClose}>
          Cancel
        </button>
      </div>
    </Modal>
  );
};
