import { useCallback, useRef, useState } from 'react';

export interface ConfirmDialogOptions {
  title: string;
  description: string;
  confirmLabel?: string;
  danger?: boolean;
}

export interface ActiveConfirmState extends ConfirmDialogOptions {
  open: boolean;
}

/**
 * Provides an async Promise-based confirmation modal replacement for blocking `window.confirm`.
 */
export function useConfirmDialog() {
  const [dialog, setDialog] = useState<ActiveConfirmState | null>(null);
  const resolverRef = useRef<((confirmed: boolean) => void) | null>(null);

  const settle = useCallback((confirmed: boolean) => {
    const resolve = resolverRef.current;
    resolverRef.current = null;
    setDialog(null);
    resolve?.(confirmed);
  }, []);

  const requestConfirm = useCallback((options: ConfirmDialogOptions): Promise<boolean> => {
    if (resolverRef.current) {
      resolverRef.current(false);
    }
    return new Promise<boolean>((resolve) => {
      resolverRef.current = resolve;
      setDialog({ ...options, open: true });
    });
  }, []);

  const cancelConfirm = useCallback(() => settle(false), [settle]);
  const acceptConfirm = useCallback(() => settle(true), [settle]);

  return {
    confirmDialog: dialog,
    requestConfirm,
    acceptConfirm,
    cancelConfirm,
  };
}
