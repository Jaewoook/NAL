import type React from 'react';
import type { TestFeedback } from '../../hooks/useNodeConnectionTest';

interface NodeFormSectionProps {
  name: string;
  url: string;
  token: string;
  saving: boolean;
  testing: boolean;
  testFeedback: TestFeedback | null;
  onNameChange: (value: string) => void;
  onUrlChange: (value: string) => void;
  onTokenChange: (value: string) => void;
  onSave: () => void;
  onTestConnection: () => void;
  onClose: () => void;
}

const INPUT_CLASS =
  'bg-slate-800 border border-slate-700 text-slate-50 px-3 py-2 rounded-md text-[13px] w-full focus:border-sky-400 focus:outline-none';

/**
 * Form section inside NodesModal for adding/updating a remote LAN agent and testing connectivity.
 */
export const NodeFormSection: React.FC<NodeFormSectionProps> = ({
  name,
  url,
  token,
  saving,
  testing,
  testFeedback,
  onNameChange,
  onUrlChange,
  onTokenChange,
  onSave,
  onTestConnection,
  onClose,
}) => {
  return (
    <div className="bg-slate-900 p-3 rounded-lg border border-slate-700 text-[13px] flex flex-col gap-2.5">
      <div className="font-bold text-xs text-slate-400 uppercase">
        Add / Update Remote Agent Node
      </div>
      <input
        id="inp-node-name"
        className={INPUT_CLASS}
        placeholder="Device Name"
        value={name}
        onChange={(e) => onNameChange(e.target.value)}
      />
      <input
        id="inp-node-url"
        className={INPUT_CLASS}
        placeholder="LAN Agent URL (e.g. http://192.168.1.50:10247)"
        value={url}
        onChange={(e) => onUrlChange(e.target.value)}
      />
      <input
        id="inp-node-token"
        className={INPUT_CLASS}
        type="password"
        placeholder="Shared X-NAL-Node-Token Secret"
        value={token}
        onChange={(e) => onTokenChange(e.target.value)}
      />
      <div className="flex gap-2 mt-1">
        <button type="button" className="btn btn-primary" disabled={saving} onClick={onSave}>
          {saving ? 'Saving...' : '+ Add / Save Node'}
        </button>
        <button
          type="button"
          id="btn-test-node"
          className="btn btn-secondary"
          disabled={testing}
          onClick={onTestConnection}
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
  );
};
