import { Dialog, DialogBackdrop, DialogPanel, DialogTitle } from '@headlessui/react';
import type React from 'react';
import { cn } from '../lib/cn';

interface ModalProps {
  id: string;
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  titleId?: string;
  panelClassName?: string;
  zIndexClassName?: string;
  children: React.ReactNode;
}

/**
 * Reusable accessible modal built on Headless UI Dialog with backdrop dismiss, focus trap, and Escape handling.
 */
export const Modal: React.FC<ModalProps> = ({
  id,
  open,
  onClose,
  title,
  titleId,
  panelClassName,
  zIndexClassName = 'z-50',
  children,
}) => {
  if (!open) return null;

  return (
    <Dialog id={id} open={open} onClose={onClose} className={cn('relative', zIndexClassName)}>
      <DialogBackdrop className="fixed inset-0 bg-slate-900/78" />
      <div className="fixed inset-0 flex items-center justify-center p-4">
        <DialogPanel
          className={cn(
            'bg-slate-800 border border-slate-700 rounded-xl p-5 w-[540px] max-w-[94vw]',
            panelClassName
          )}
        >
          <DialogTitle
            id={titleId}
            as="h3"
            className="text-base font-bold flex items-center gap-2 flex-wrap"
          >
            {title}
          </DialogTitle>
          {children}
        </DialogPanel>
      </div>
    </Dialog>
  );
};
