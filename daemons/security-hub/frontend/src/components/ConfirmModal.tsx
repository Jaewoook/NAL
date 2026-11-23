import type React from 'react';
import type { ActiveConfirmState } from '../hooks/useConfirmDialog';
import { cn } from '../lib/cn';
import { Modal } from './Modal';

interface ConfirmModalProps {
  state: ActiveConfirmState | null;
  onConfirm: () => void;
  onCancel: () => void;
}

/**
 * Accessible dark-themed confirmation modal replacing native `window.confirm` popups.
 */
export const ConfirmModal: React.FC<ConfirmModalProps> = ({ state, onConfirm, onCancel }) => {
  return (
    <Modal
      id="modal-confirm"
      open={Boolean(state?.open)}
      onClose={onCancel}
      titleId="modal-confirm-title"
      title={state?.title || 'Confirm Action'}
      zIndexClassName="z-60"
    >
      {state && (
        <>
          <p className="text-slate-400 text-[13px] mt-2.5 mb-5">{state.description}</p>
          <div className="flex justify-end gap-2.5">
            <button
              type="button"
              id="btn-confirm-dialog"
              className={cn('btn', state.danger ? 'btn-danger' : 'btn-primary')}
              onClick={onConfirm}
            >
              {state.confirmLabel || 'Confirm'}
            </button>
            <button type="button" className="btn btn-ghost" onClick={onCancel}>
              Cancel
            </button>
          </div>
        </>
      )}
    </Modal>
  );
};
