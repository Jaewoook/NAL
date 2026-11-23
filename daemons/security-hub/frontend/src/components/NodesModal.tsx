import type React from 'react';
import { useCallback, useEffect, useRef, useState } from 'react';
import { toast } from 'sonner';
import { useNodeConnectionTest } from '../hooks/useNodeConnectionTest';
import type { NodeInfo } from '../types';
import { Modal } from './Modal';
import { NodeFormSection } from './nodes/NodeFormSection';
import { PendingNodesSection } from './nodes/PendingNodesSection';
import { RegisteredNodesList } from './nodes/RegisteredNodesList';

interface NodesModalProps {
  open: boolean;
  nodes: NodeInfo[];
  onApproveNode: (name: string) => void;
  onRejectNode: (name: string) => void;
  onDeleteNode: (name: string) => void;
  onSaveNode: (name: string, url: string, token: string) => Promise<boolean>;
  onUnauthorized?: () => void;
  onClose: () => void;
}

/**
 * Modal coordinating pending agent approvals, registered node management, and connection testing.
 */
export const NodesModal: React.FC<NodesModalProps> = ({
  open,
  nodes,
  onApproveNode,
  onRejectNode,
  onDeleteNode,
  onSaveNode,
  onUnauthorized,
  onClose,
}) => {
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [token, setToken] = useState('');
  const [saving, setSaving] = useState(false);
  const openEpochRef = useRef(0);

  const handleAutoFillName = useCallback((discoveredName: string) => {
    setName((prev) => (prev.trim() ? prev : discoveredName));
  }, []);

  const connectionTest = useNodeConnectionTest({
    open,
    onAutoFillName: handleAutoFillName,
    onUnauthorized,
  });

  useEffect(() => {
    if (!open) {
      openEpochRef.current += 1;
      setSaving(false);
    }
  }, [open]);

  useEffect(() => {
    return () => {
      openEpochRef.current += 1;
    };
  }, []);

  const handleSave = async () => {
    if (saving) return;
    const trimmedName = name.trim();
    const trimmedUrl = url.trim();
    const trimmedToken = token.trim();
    if (!trimmedName || !trimmedUrl) {
      toast.error('Please provide both the device name and the LAN Agent URL.');
      return;
    }
    const epoch = openEpochRef.current;
    setSaving(true);
    try {
      const ok = await onSaveNode(trimmedName, trimmedUrl, trimmedToken);
      if (epoch !== openEpochRef.current) return;
      if (ok) {
        connectionTest.resetTest();
        setName('');
        setUrl('');
        setToken('');
      }
    } finally {
      if (epoch === openEpochRef.current) {
        setSaving(false);
      }
    }
  };

  const pendingNodes = nodes.filter((n) => n.status === 'pending');
  const activeNodes = nodes.filter((n) => !n.status || n.status === 'approved');
  const rejectedNodes = nodes.filter((n) => n.status === 'rejected');

  return (
    <Modal
      id="modal-nodes"
      open={open}
      onClose={onClose}
      titleId="modal-nodes-title"
      title="Manage Compute Nodes (Hub & LAN Agents)"
      panelClassName="max-h-[90vh] overflow-y-auto"
    >
      <p className="text-slate-400 text-[13px] mt-2 mb-3.5">
        Register LAN servers running <code>./security-hub agent</code>. Uninstalled or stopped
        components (such as Docker) are ignored automatically.
      </p>

      <PendingNodesSection
        pendingNodes={pendingNodes}
        onApproveNode={onApproveNode}
        onRejectNode={onRejectNode}
      />

      <RegisteredNodesList
        activeNodes={activeNodes}
        rejectedNodes={rejectedNodes}
        onApproveNode={onApproveNode}
        onDeleteNode={onDeleteNode}
      />

      <NodeFormSection
        name={name}
        url={url}
        token={token}
        saving={saving}
        testing={connectionTest.testing}
        testFeedback={connectionTest.testFeedback}
        onNameChange={setName}
        onUrlChange={setUrl}
        onTokenChange={setToken}
        onSave={() => void handleSave()}
        onTestConnection={() => void connectionTest.runTest(url, token)}
        onClose={onClose}
      />
    </Modal>
  );
};
