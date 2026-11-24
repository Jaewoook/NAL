import type React from 'react';
import type { ActiveConfirmState } from '../hooks/useConfirmDialog';
import { Modal } from './Modal';
import { Button } from './ui';

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
            <Button
              id="btn-confirm-dialog"
              variant={state.danger ? 'danger' : 'primary'}
              onClick={onConfirm}
            >
              {state.confirmLabel || 'Confirm'}
            </Button>
            <Button variant="ghost" onClick={onCancel}>
              Cancel
            </Button>
          </div>
        </>
      )}
    </Modal>
  );
};
