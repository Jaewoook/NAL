import type React from 'react';
import { useEffect, useState } from 'react';
import type { PendingUpdateRequest } from '../types';
import { Modal } from './Modal';

interface UpdateModalProps {
  request: PendingUpdateRequest | null;
  onConfirm: (req: PendingUpdateRequest, runBackup: boolean, enableDeadMan: boolean) => void;
  onClose: () => void;
}

/**
 * Confirmation dialog for applying Docker container or host package upgrades.
 */
export const UpdateModal: React.FC<UpdateModalProps> = ({ request, onConfirm, onClose }) => {
  const [runBackup, setRunBackup] = useState(false);
  const [enableDeadMan, setEnableDeadMan] = useState(true);

  useEffect(() => {
    if (request) {
      setRunBackup(Boolean(request.stateful));
      setEnableDeadMan(true);
    }
  }, [request]);

  const isDocker = request?.target_type === 'docker';

  return (
    <Modal
      id="modal-update"
      open={Boolean(request)}
      onClose={onClose}
      title={
        request ? (
          <>
            <span id="modal-title">
              Confirm Update on [{request.node}]: {request.target_name}
            </span>
            {isDocker && (
              <span className="badge warn" id="modal-crit-badge">
                60s Dead-Man&apos;s Rollback
              </span>
            )}
          </>
        ) : null
      }
    >
      {request && (
        <>
          <p id="modal-desc" className="text-slate-400 text-[13px] mt-2.5 mb-4">
            Updating {request.target_name} on {request.node} from {request.current_version} →{' '}
            {request.target_version}
          </p>

          {isDocker && (
            <div className="bg-slate-900 p-3 rounded-lg border border-slate-700 text-[13px] flex flex-col gap-2.5">
              <label id="lbl-snapshot" className="flex gap-2 items-center">
                <input type="checkbox" checked readOnly disabled />
                <span>
                  <strong>Save Rollback Snapshot</strong> (records current image digest &amp;
                  compose/env files)
                </span>
              </label>
              <label id="lbl-deadman" className="flex gap-2 items-center cursor-pointer">
                <input
                  type="checkbox"
                  id="chk-deadman"
                  checked={enableDeadMan}
                  onChange={(e) => setEnableDeadMan(e.target.checked)}
                />
                <span>
                  <strong>60s Automatic Dead-Man&apos;s Rollback</strong> if container healthcheck
                  fails
                </span>
              </label>
              <label id="lbl-backup" className="flex gap-2 items-center cursor-pointer">
                <input
                  type="checkbox"
                  id="chk-backup"
                  checked={runBackup}
                  onChange={(e) => setRunBackup(e.target.checked)}
                />
                <span>
                  <strong>Run Pre-Update Volume Backup</strong> (
                  <code>./batch/backup-volumes.sh</code>)
                </span>
              </label>
            </div>
          )}

          <div className="flex gap-2.5 mt-4">
            <button
              type="button"
              id="btn-confirm-update"
              className="btn btn-primary"
              onClick={() => onConfirm(request, runBackup, enableDeadMan)}
            >
              {isDocker ? 'Pull & Apply Update' : 'Apply Package Upgrade'}
            </button>
            <button type="button" className="btn btn-ghost" onClick={onClose}>
              Cancel
            </button>
          </div>
        </>
      )}
    </Modal>
  );
};
