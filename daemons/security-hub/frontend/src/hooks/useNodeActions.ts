import { type MutableRefObject, useCallback } from 'react';
import { toast } from 'sonner';
import { hubApi } from '../lib/http';
import { useApiMutation } from './useApiMutation';
import type { ConfirmDialogOptions } from './useConfirmDialog';

export interface UseNodeActionsOptions {
  currentNodeFilter: string;
  authEpochRef: MutableRefObject<number>;
  onUnauthorized: () => void;
  refreshDashboard: () => Promise<void>;
  onResetNodeFilter: () => void;
  requestConfirm: (options: ConfirmDialogOptions) => Promise<boolean>;
}

/**
 * Encapsulates compute node registry mutations (`approveNode`, `rejectNode`, `saveNode`, `deleteNode`).
 */
export function useNodeActions({
  currentNodeFilter,
  authEpochRef,
  onUnauthorized,
  refreshDashboard,
  onResetNodeFilter,
  requestConfirm,
}: UseNodeActionsOptions) {
  const apiMutation = useApiMutation({
    authEpochRef,
    onUnauthorized,
    refreshDashboard,
  });

  const approveNode = useCallback(
    (name: string) => {
      apiMutation.mutate({
        config: hubApi.approveNodeConfig(name),
        errPrefix: 'Failed to approve node',
      });
    },
    [apiMutation]
  );

  const rejectNode = useCallback(
    async (name: string) => {
      const confirmed = await requestConfirm({
        title: 'Dismiss Agent Registration',
        description: `Dismiss pending registration for "${name}"?`,
        confirmLabel: 'Dismiss',
        danger: true,
      });
      if (!confirmed) return;

      apiMutation.mutate({
        config: hubApi.rejectNodeConfig(name),
        errPrefix: 'Failed to dismiss node',
      });
    },
    [apiMutation, requestConfirm]
  );

  const saveNode = useCallback(
    async (name: string, url: string, token: string): Promise<boolean> => {
      const epoch = authEpochRef.current;
      try {
        await apiMutation.mutateAsync({
          config: hubApi.saveNodeConfig(name, url, token),
          errPrefix: 'Failed to save node',
        });
        if (epoch !== authEpochRef.current) return false;
        toast.success(`Saved node "${name}"`);
        return true;
      } catch {
        return false;
      }
    },
    [apiMutation, authEpochRef]
  );

  const deleteNode = useCallback(
    async (name: string) => {
      const confirmed = await requestConfirm({
        title: 'Remove Compute Node',
        description: `Remove compute node "${name}" from the registry?`,
        confirmLabel: 'Remove Node',
        danger: true,
      });
      if (!confirmed) return;

      apiMutation.mutate(
        {
          config: hubApi.deleteNodeConfig(name),
          errPrefix: 'Failed to remove node',
        },
        {
          onSuccess: (_data, _variables, context) => {
            if (context && context.epoch !== authEpochRef.current) return;
            if (currentNodeFilter === name) onResetNodeFilter();
          },
        }
      );
    },
    [apiMutation, authEpochRef, currentNodeFilter, onResetNodeFilter, requestConfirm]
  );

  return {
    approveNode,
    rejectNode,
    saveNode,
    deleteNode,
  };
}
