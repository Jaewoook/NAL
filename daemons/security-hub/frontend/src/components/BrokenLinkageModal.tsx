import type React from 'react';
import { Modal } from './Modal';
import { Badge } from './ui/Badge';
import { Button } from './ui/Button';

interface BrokenLinkageModalProps {
  pkgName: string;
  details: string;
  open: boolean;
  onClose: () => void;
}

/**
 * Displays dynamic linker / shared library diagnostics for packages flagged with broken linkage.
 */
export const BrokenLinkageModal: React.FC<BrokenLinkageModalProps> = ({
  pkgName,
  details,
  open,
  onClose,
}) => {
  return (
    <Modal
      id="modal-linkage"
      open={open}
      onClose={onClose}
      titleId="modal-linkage-title"
      title={
        <>
          <span>Broken Linkage Details</span>
          <Badge tone="crit" id="modal-linkage-pkg">
            {pkgName}
          </Badge>
        </>
      }
    >
      <p className="text-slate-400 text-[13px] mt-2.5 mb-3.5">
        Dynamic linker dependencies, shared libraries (.dylib / .so), or package dependencies are
        missing or unsatisfied:
      </p>
      <div
        className="bg-[#090d16] border border-slate-700 rounded-lg font-mono text-[12.5px] leading-relaxed text-slate-200 p-4 max-h-[260px] overflow-y-auto mb-4 whitespace-pre-wrap break-all"
        id="modal-linkage-body"
      >
        {details || 'Missing shared library dependency'}
      </div>
      <div className="flex justify-end gap-2.5">
        <Button variant="ghost" onClick={onClose}>
          Close
        </Button>
      </div>
    </Modal>
  );
};
