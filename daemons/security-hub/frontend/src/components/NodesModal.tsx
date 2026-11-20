import React, { useEffect, useRef, useState } from 'react';
import { toast } from 'sonner';
import { apiClient, cn, getAxiosErrorMessage, isAxiosUnauthorized } from '../api';
import type { NodeInfo, NodeTestResponse } from '../types';
import { Modal } from './Modal';

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

type TestFeedback =
  | { kind: 'info'; text: string }
  | { kind: 'ok'; latency?: string; osVersion: string }
  | { kind: 'error'; text: string };

/**
 * Modal for reviewing pending agent registrations, managing approved nodes, and testing connectivity.
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
  const [testing, setTesting] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testFeedback, setTestFeedback] = useState<TestFeedback | null>(null);
  const testReqIdRef = useRef(0);
  const openEpochRef = useRef(0);

  useEffect(() => {
    if (!open) {
      openEpochRef.current += 1;
      testReqIdRef.current += 1;
      setTestFeedback(null);
      setTesting(false);
      setSaving(false);
    }
  }, [open]);

  useEffect(() => {
    return () => {
      openEpochRef.current += 1;
      testReqIdRef.current += 1;
    };
  }, []);

  const pendingNodes = nodes.filter((n) => n.status === 'pending');
  const activeNodes = nodes.filter((n) => !n.status || n.status === 'approved');
  const rejectedNodes = nodes.filter((n) => n.status === 'rejected');

  const handleTestConnection = async () => {
    const trimmedUrl = url.trim();
    const trimmedToken = token.trim();
    if (!trimmedUrl) {
      testReqIdRef.current += 1;
      setTesting(false);
      setTestFeedback({ kind: 'error', text: 'Please provide the LAN Agent URL to test.' });
      return;
    }

    const reqId = ++testReqIdRef.current;
    const openEpoch = openEpochRef.current;
    setTesting(true);
    setTestFeedback({ kind: 'info', text: `Connecting to ${trimmedUrl}...` });

    try {
      const res = await apiClient.post<NodeTestResponse>('/api/nodes/test', {
        url: trimmedUrl,
        token: trimmedToken,
      });
      if (reqId !== testReqIdRef.current || openEpoch !== openEpochRef.current) return;
      const data = res.data;
      if (!data || typeof data !== 'object') {
        setTestFeedback({
          kind: 'error',
          text: `Connection failed: ${res.statusText || `HTTP ${res.status}`}`,
        });
        return;
      }
      if (data.ok) {
        const osVersion = data.os_version || data.info?.os_version || 'Unknown OS';
        const latency = data.latency_ms !== undefined ? `${data.latency_ms}ms` : '';
        setTestFeedback({ kind: 'ok', latency, osVersion });
        if (!name.trim() && data.info?.name) {
          setName(data.info.name);
        }
      } else {
        setTestFeedback({
          kind: 'error',
          text: `Connection failed: ${data.error || 'Agent unreachable'}`,
        });
      }
    } catch (err) {
      if (reqId !== testReqIdRef.current || openEpoch !== openEpochRef.current) return;
      if (isAxiosUnauthorized(err)) {
        onUnauthorized?.();
        return;
      }
      setTestFeedback({
        kind: 'error',
        text: `Connection failed: ${getAxiosErrorMessage(err, 'Agent unreachable')}`,
      });
    } finally {
      if (reqId === testReqIdRef.current && openEpoch === openEpochRef.current) {
        setTesting(false);
      }
    }
  };

  const handleSave = async () => {
    if (saving) return;
    const trimmedName = name.trim();
    const trimmedUrl = url.trim();
    const trimmedToken = token.trim();
    if (!trimmedName || !trimmedUrl) {
      toast.error('Please provide both the device name and the LAN Agent URL.');
      return;
    }
    const openEpoch = openEpochRef.current;
    setSaving(true);
    try {
      const ok = await onSaveNode(trimmedName, trimmedUrl, trimmedToken);
      if (openEpoch !== openEpochRef.current) return;
      if (ok) {
        testReqIdRef.current += 1;
        setTesting(false);
        setName('');
        setUrl('');
        setToken('');
        setTestFeedback(null);
      }
    } finally {
      if (openEpoch === openEpochRef.current) {
        setSaving(false);
      }
    }
  };

  const inputClass =
    'bg-slate-800 border border-slate-700 text-slate-50 px-3 py-2 rounded-md text-[13px] w-full focus:border-sky-400 focus:outline-none';

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
        Register LAN servers running <code>./security-hub agent</code>. Uninstalled or stopped components (such as Docker) are ignored automatically.
      </p>

      {pendingNodes.length > 0 && (
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
                  <button type="button" className="btn btn-primary" onClick={() => onApproveNode(n.name)}>
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
      )}

      <div className="font-bold text-xs text-slate-400 uppercase mb-1.5">Registered Compute Nodes</div>

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
              <span className={cn('dot', n.online ? 'green' : 'amber')} />{' '}
              <strong>{n.name}</strong>
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
                  <div className="text-xs text-slate-400 font-mono break-all">{n.url || 'LAN Node'}</div>
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

      <div className="bg-slate-900 p-3 rounded-lg border border-slate-700 text-[13px] flex flex-col gap-2.5">
        <div className="font-bold text-xs text-slate-400 uppercase">Add / Update Remote Agent Node</div>
        <input
          id="inp-node-name"
          className={inputClass}
          placeholder="Device Name"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <input
          id="inp-node-url"
          className={inputClass}
          placeholder="LAN Agent URL (e.g. http://192.168.1.50:10247)"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
        />
        <input
          id="inp-node-token"
          className={inputClass}
          type="password"
          placeholder="Shared X-NAL-Node-Token Secret"
          value={token}
          onChange={(e) => setToken(e.target.value)}
        />
        <div className="flex gap-2 mt-1">
          <button type="button" className="btn btn-primary" disabled={saving} onClick={handleSave}>
            {saving ? 'Saving...' : '+ Add / Save Node'}
          </button>
          <button
            type="button"
            id="btn-test-node"
            className="btn btn-secondary"
            disabled={testing}
            onClick={handleTestConnection}
          >
            {testing ? '⚡ Testing...' : '⚡ Test Connection'}
          </button>
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Close
          </button>
        </div>

        {testFeedback && (
          <div id="test-node-result" className="mt-2">
            {testFeedback.kind === 'info' && (
              <div className="badge warn w-full justify-start px-3 py-2">{testFeedback.text}</div>
            )}
            {testFeedback.kind === 'ok' && (
              <div className="badge ok w-full justify-start px-3 py-2 gap-2">
                <span>✓ Connected!</span>
                {testFeedback.latency && <span>({testFeedback.latency})</span>}
                <span>OS: {testFeedback.osVersion}</span>
              </div>
            )}
            {testFeedback.kind === 'error' && (
              <div className="badge crit w-full justify-start px-3 py-2">✖ {testFeedback.text}</div>
            )}
          </div>
        )}
      </div>
    </Modal>
  );
};
